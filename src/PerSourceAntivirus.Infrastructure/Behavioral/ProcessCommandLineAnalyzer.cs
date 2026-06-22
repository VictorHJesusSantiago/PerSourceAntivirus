using System.Collections.Concurrent;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

[SupportedOSPlatform("windows")]
public sealed class ProcessCommandLineAnalyzer : IProcessCommandLineAnalyzer
{
    private static readonly (string Pattern, int Score, string Label)[] CmdlinePatterns =
    [
        ("-EncodedCommand",          30, "PS-EncodedCommand"),
        ("-WindowStyle Hidden",      15, "PS-HiddenWindow"),
        ("-NonInteractive",          10, "PS-NonInteractive"),
        ("Bypass",                   15, "PS-BypassExecPolicy"),
        ("IEX",                      20, "PS-IEX"),
        ("Invoke-Expression",        20, "PS-InvokeExpression"),
        ("DownloadString",           25, "PS-DownloadString"),
        ("downloadstring",           25, "PS-DownloadString"),
        ("WebClient",                15, "PS-WebClient"),
        (@"C:\Users\.*\\AppData\\Temp", 20, "TempPath"),
        (@"C:\Windows\Temp",         20, "WindowsTemp"),
        ("echo.*>.*\\.bat",          25, "EchoBat"),
        ("^ ",                       15, "CMD-EscapeChar"),
        (@"> nul",                   10, "CMD-NullRedirect"),
        ("wscript.*temp",            25, "WScript-TempFile"),
        ("cscript.*temp",            25, "CScript-TempFile"),
        ("-nop",                     10, "PS-NoProfile"),
        ("-noprofile",               10, "PS-NoProfile"),
        ("-sta",                      5, "PS-STA"),
    ];

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<int, DateTime> _recentlyAlerted = new();
    private CancellationTokenSource? _cts;

    public event EventHandler<ProcessCommandLineAlertEventArgs>? AlertDetected;

    public ProcessCommandLineAnalyzer(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        await Task.Run(() => PollLoopAsync(_cts.Token), _cts.Token).ConfigureAwait(false);
    }

    public void StopMonitoring() => _cts?.Cancel();

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                ScanProcessCommandLines();
                PruneRecentAlerts();
            }
            catch { }

            await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        }
    }

    private void ScanProcessCommandLines()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE CommandLine IS NOT NULL");
            using var results = searcher.Get();

            foreach (ManagementObject obj in results)
            {
                try
                {
                    var pid = Convert.ToInt32(obj["ProcessId"]);
                    var name = obj["Name"] as string ?? string.Empty;
                    var cmdLine = obj["CommandLine"] as string ?? string.Empty;

                    if (string.IsNullOrWhiteSpace(cmdLine))
                        continue;

                    if (_recentlyAlerted.TryGetValue(pid, out var lastAlert))
                    {
                        if (DateTime.UtcNow - lastAlert < TimeSpan.FromMinutes(5))
                            continue;
                    }

                    var (score, triggers) = ScoreCommandLine(cmdLine);
                    if (score < 30)
                        continue;

                    var severity = score >= 70 ? 9 : score >= 50 ? 7 : 5;

                    _recentlyAlerted[pid] = DateTime.UtcNow;

                    var alert = new ProcessCommandLineAlert
                    {
                        Id = Guid.NewGuid(),
                        ProcessName = name,
                        ProcessId = pid,
                        CommandLine = cmdLine.Length > 500 ? cmdLine[..500] : cmdLine,
                        Triggers = string.Join(", ", triggers),
                        SuspicionScore = score,
                        Severity = severity,
                        DetectedAtUtc = DateTime.UtcNow
                    };

                    try
                    {
                        using var scope = _scopeFactory.CreateScope();
                        var repo = scope.ServiceProvider.GetRequiredService<IProcessCommandLineAlertRepository>();
                        repo.AddAsync(alert, CancellationToken.None).GetAwaiter().GetResult();
                    }
                    catch { }

                    AlertDetected?.Invoke(this, new ProcessCommandLineAlertEventArgs(alert));
                }
                catch { }
            }
        }
        catch { }
    }

    private static (int Score, List<string> Triggers) ScoreCommandLine(string cmdLine)
    {
        var totalScore = 0;
        var triggeredLabels = new List<string>();
        var seen = new HashSet<string>();

        foreach (var (pattern, score, label) in CmdlinePatterns)
        {
            try
            {
                bool matched;
                if (pattern.StartsWith("^") || pattern.Contains(".*") || pattern.Contains(@"\\"))
                {
                    matched = Regex.IsMatch(cmdLine, pattern, RegexOptions.IgnoreCase);
                }
                else
                {
                    matched = cmdLine.Contains(pattern, StringComparison.OrdinalIgnoreCase);
                }

                if (matched && seen.Add(label))
                {
                    totalScore += score;
                    triggeredLabels.Add(label);
                }
            }
            catch { }
        }

        return (totalScore, triggeredLabels);
    }

    private void PruneRecentAlerts()
    {
        var threshold = DateTime.UtcNow - TimeSpan.FromMinutes(10);
        foreach (var kvp in _recentlyAlerted)
        {
            if (kvp.Value < threshold)
                _recentlyAlerted.TryRemove(kvp.Key, out _);
        }
    }
}
