using System.Management;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Wmi;

[SupportedOSPlatform("windows")]
public class WmiPersistenceScanner : IWmiPersistenceScanner
{
    private static readonly HashSet<string> HighRiskExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh.exe", "pwsh",
        "wscript.exe", "wscript", "cscript.exe", "cscript"
    };

    public Task<IReadOnlyList<WmiPersistenceAlert>> ScanAsync(CancellationToken ct = default)
    {
        return Task.FromResult(ScanInternal());
    }

    private IReadOnlyList<WmiPersistenceAlert> ScanInternal()
    {
        var alerts = new List<WmiPersistenceAlert>();

        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            var filters = LoadFilters(scope);
            var consumers = LoadConsumers(scope);
            var bindings = LoadBindings(scope);

            foreach (var binding in bindings)
            {
                try
                {
                    var filterRef = binding.FilterRef;
                    var consumerRef = binding.ConsumerRef;

                    if (!filters.TryGetValue(filterRef, out var filter))
                        continue;
                    if (!consumers.TryGetValue(consumerRef, out var consumer))
                        continue;

                    var scriptOrCommand = consumer.ScriptOrCommand;
                    var severity = DetermineSeverity(scriptOrCommand, consumer.ConsumerType);

                    alerts.Add(new WmiPersistenceAlert
                    {
                        DetectedAtUtc = DateTime.UtcNow,
                        FilterName = filter.Name,
                        ConsumerName = consumer.Name,
                        ConsumerType = consumer.ConsumerType,
                        QueryLanguage = filter.QueryLanguage,
                        Query = filter.Query,
                        ScriptOrCommand = scriptOrCommand,
                        Severity = severity,
                        IsAcknowledged = false
                    });
                }
                catch { }
            }
        }
        catch { }

        return alerts.AsReadOnly();
    }

    private static string DetermineSeverity(string scriptOrCommand, string consumerType)
    {
        if (string.IsNullOrWhiteSpace(scriptOrCommand))
            return "High";

        var lower = scriptOrCommand.ToLowerInvariant();
        foreach (var exe in HighRiskExecutables)
        {
            if (lower.Contains(exe.ToLowerInvariant()))
                return "Critical";
        }

        return "High";
    }

    private static Dictionary<string, FilterInfo> LoadFilters(ManagementScope scope)
    {
        var result = new Dictionary<string, FilterInfo>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter"));
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    var name = obj["Name"]?.ToString() ?? string.Empty;
                    var queryLang = obj["QueryLanguage"]?.ToString() ?? string.Empty;
                    var query = obj["Query"]?.ToString() ?? string.Empty;
                    var path = obj.Path.RelativePath;
                    result[path] = new FilterInfo(name, queryLang, query);
                    result[name] = new FilterInfo(name, queryLang, query);
                }
                catch { }
                finally { obj.Dispose(); }
            }
        }
        catch { }

        return result;
    }

    private static Dictionary<string, ConsumerInfo> LoadConsumers(ManagementScope scope)
    {
        var result = new Dictionary<string, ConsumerInfo>(StringComparer.OrdinalIgnoreCase);

        LoadConsumerClass(scope, "CommandLineEventConsumer", result, obj =>
        {
            var name = obj["Name"]?.ToString() ?? string.Empty;
            var execPath = obj["ExecutablePath"]?.ToString() ?? string.Empty;
            var cmdTemplate = obj["CommandLineTemplate"]?.ToString() ?? string.Empty;
            var combined = string.IsNullOrEmpty(execPath) ? cmdTemplate : $"{execPath} {cmdTemplate}".Trim();
            return new ConsumerInfo(name, "CommandLineEventConsumer", combined);
        });

        LoadConsumerClass(scope, "ActiveScriptEventConsumer", result, obj =>
        {
            var name = obj["Name"]?.ToString() ?? string.Empty;
            var scriptText = obj["ScriptText"]?.ToString() ?? string.Empty;
            return new ConsumerInfo(name, "ActiveScriptEventConsumer", scriptText);
        });

        LoadConsumerClass(scope, "__EventConsumer", result, obj =>
        {
            var name = obj["Name"]?.ToString() ?? string.Empty;
            var type = obj.SystemProperties["__CLASS"]?.Value?.ToString() ?? "__EventConsumer";
            return new ConsumerInfo(name, type, string.Empty);
        });

        return result;
    }

    private static void LoadConsumerClass(
        ManagementScope scope,
        string className,
        Dictionary<string, ConsumerInfo> result,
        Func<ManagementObject, ConsumerInfo> extractor)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {className}"));
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    var info = extractor(obj);
                    var path = obj.Path.RelativePath;
                    result[path] = info;
                    if (!string.IsNullOrEmpty(info.Name))
                        result[info.Name] = info;
                }
                catch { }
                finally { obj.Dispose(); }
            }
        }
        catch { }
    }

    private static List<BindingInfo> LoadBindings(ManagementScope scope)
    {
        var result = new List<BindingInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding"));
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    var filterRef = obj["Filter"]?.ToString() ?? string.Empty;
                    var consumerRef = obj["Consumer"]?.ToString() ?? string.Empty;

                    filterRef = NormalizeRef(filterRef);
                    consumerRef = NormalizeRef(consumerRef);

                    result.Add(new BindingInfo(filterRef, consumerRef));
                }
                catch { }
                finally { obj.Dispose(); }
            }
        }
        catch { }

        return result;
    }

    private static string NormalizeRef(string wmiPath)
    {
        if (string.IsNullOrEmpty(wmiPath))
            return wmiPath;

        var idx = wmiPath.IndexOf(':');
        if (idx >= 0 && idx < wmiPath.Length - 1)
            return wmiPath[(idx + 1)..];

        return wmiPath;
    }

    private sealed record FilterInfo(string Name, string QueryLanguage, string Query);
    private sealed record ConsumerInfo(string Name, string ConsumerType, string ScriptOrCommand);
    private sealed record BindingInfo(string FilterRef, string ConsumerRef);
}
