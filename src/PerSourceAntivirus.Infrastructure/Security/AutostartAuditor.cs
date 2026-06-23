using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class AutostartAuditor : IAutostartAuditor
{
    private static readonly HashSet<string> KnownSystemPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation", "Microsoft Windows", "Windows", "Microsoft"
    };

    private static readonly string[] SuspiciousDirs =
    [
        @"C:\Users\", @"C:\Temp\", @"C:\Windows\Temp\", @"%TEMP%", @"%TMP%", @"%APPDATA%\Temp"
    ];

    public async Task<IReadOnlyList<AutostartEntry>> AuditAsync(CancellationToken ct)
    {
        var results = new List<AutostartEntry>();
        var now = DateTime.UtcNow;

        await Task.Run(() =>
        {
            EnumerateRunKeys(results, now, ct);
            EnumerateAppInitDlls(results, now);
            EnumerateLsaPackages(results, now);
            EnumerateIfeo(results, now);
            EnumerateStartupFolders(results, now);
            EnumerateScheduledTasks(results, now, ct);
            EnumerateAutoServices(results, now, ct);
        }, ct);

        return results;
    }

    private static void EnumerateRunKeys(List<AutostartEntry> results, DateTime now, CancellationToken ct)
    {
        var keys = new[]
        {
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",        "HKLM\\Run"),
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",    "HKLM\\RunOnce"),
            (@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",         "HKCU\\Run"),
            (@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",     "HKCU\\RunOnce"),
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",     "HKLM\\Run(WOW)"),
            (@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce(WOW)"),
        };

        foreach (var (keyPath, location) in keys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(
                    keyPath.StartsWith("HKEY_LOCAL_MACHINE") ? RegistryHive.LocalMachine : RegistryHive.CurrentUser,
                    RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath.Substring(keyPath.IndexOf('\\') + 1));

                if (key == null) continue;
                foreach (var valueName in key.GetValueNames())
                {
                    var cmd = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    var isSuspicious = IsSuspiciousCommand(cmd);
                    results.Add(new AutostartEntry
                    {
                        Id = Guid.NewGuid(),
                        Location = location,
                        EntryName = valueName,
                        Command = cmd,
                        Publisher = string.Empty,
                        IsKnown = IsKnownSystemPath(cmd),
                        IsSuspicious = isSuspicious,
                        Classification = isSuspicious ? "Suspicious" : IsKnownSystemPath(cmd) ? "Known" : "Unknown",
                        Severity = isSuspicious ? 7 : 3,
                        AuditedAtUtc = now
                    });
                }
            }
            catch { }
        }
    }

    private static void EnumerateAppInitDlls(List<AutostartEntry> results, DateTime now)
    {
        try
        {
            const string keyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key == null) return;
            var value = key.GetValue("AppInit_DLLs")?.ToString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value)) return;
            results.Add(new AutostartEntry
            {
                Id = Guid.NewGuid(),
                Location = "HKLM\\AppInit_DLLs",
                EntryName = "AppInit_DLLs",
                Command = value,
                Publisher = string.Empty,
                IsKnown = false,
                IsSuspicious = true,
                Classification = "Suspicious",
                Severity = 8,
                AuditedAtUtc = now
            });
        }
        catch { }
    }

    private static void EnumerateLsaPackages(List<AutostartEntry> results, DateTime now)
    {
        var lsaValues = new[]
        {
            (@"SYSTEM\CurrentControlSet\Control\Lsa", "Authentication Packages"),
            (@"SYSTEM\CurrentControlSet\Control\Lsa", "Security Packages"),
            (@"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig", "Security Packages"),
        };

        var knownPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "msv1_0", "kerberos", "wdigest", "tspkg", "pku2u", "cloudap",
            "schannel", "negotiate", "ntlm", "livessp", ""
        };

        foreach (var (keyPath, valueName) in lsaValues)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key == null) continue;
                var packages = key.GetValue(valueName) as string[];
                if (packages == null) continue;
                foreach (var pkg in packages.Where(p => !string.IsNullOrWhiteSpace(p)))
                {
                    var isSuspicious = !knownPackages.Contains(pkg);
                    results.Add(new AutostartEntry
                    {
                        Id = Guid.NewGuid(),
                        Location = $"HKLM\\{keyPath}\\{valueName}",
                        EntryName = valueName,
                        Command = pkg,
                        Publisher = string.Empty,
                        IsKnown = !isSuspicious,
                        IsSuspicious = isSuspicious,
                        Classification = isSuspicious ? "Suspicious" : "Known",
                        Severity = isSuspicious ? 8 : 2,
                        AuditedAtUtc = now
                    });
                }
            }
            catch { }
        }
    }

    private static void EnumerateIfeo(List<AutostartEntry> results, DateTime now)
    {
        try
        {
            const string keyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key == null) return;
            foreach (var subKeyName in key.GetSubKeyNames())
            {
                try
                {
                    using var sub = key.OpenSubKey(subKeyName);
                    var debugger = sub?.GetValue("Debugger")?.ToString();
                    if (string.IsNullOrWhiteSpace(debugger)) continue;
                    results.Add(new AutostartEntry
                    {
                        Id = Guid.NewGuid(),
                        Location = $"HKLM\\IFEO\\{subKeyName}",
                        EntryName = subKeyName,
                        Command = debugger,
                        Publisher = string.Empty,
                        IsKnown = false,
                        IsSuspicious = true,
                        Classification = "Suspicious",
                        Severity = 9,
                        AuditedAtUtc = now
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static void EnumerateStartupFolders(List<AutostartEntry> results, DateTime now)
    {
        var folders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup),       "UserStartup"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "CommonStartup"),
        };

        foreach (var (folder, location) in folders)
        {
            if (!Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*.*"))
                {
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".exe" or ".bat" or ".cmd" or ".vbs" or ".ps1" or ".lnk" or ".js")) continue;
                    results.Add(new AutostartEntry
                    {
                        Id = Guid.NewGuid(),
                        Location = location,
                        EntryName = Path.GetFileName(file),
                        Command = file,
                        Publisher = string.Empty,
                        IsKnown = IsKnownSystemPath(file),
                        IsSuspicious = IsSuspiciousCommand(file),
                        Classification = IsSuspiciousCommand(file) ? "Suspicious" : "Unknown",
                        Severity = 5,
                        AuditedAtUtc = now
                    });
                }
            }
            catch { }
        }
    }

    private static void EnumerateScheduledTasks(List<AutostartEntry> results, DateTime now, CancellationToken ct)
    {
        try
        {
            using var proc = new SysProcess();
            proc.StartInfo = new System.Diagnostics.ProcessStartInfo("schtasks.exe", "/query /fo CSV /nh /v")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            foreach (var line in output.Split('\n'))
            {
                if (ct.IsCancellationRequested) return;
                var parts = SplitCsv(line);
                if (parts.Length < 9) continue;
                var taskName = parts[0].Trim('"', ' ');
                var taskRun  = parts[8].Trim('"', ' ');
                if (string.IsNullOrWhiteSpace(taskName) || taskName.Equals("TaskName", StringComparison.OrdinalIgnoreCase))
                    continue;

                var isSuspicious = IsSuspiciousCommand(taskRun);
                results.Add(new AutostartEntry
                {
                    Id = Guid.NewGuid(),
                    Location = "ScheduledTask",
                    EntryName = taskName,
                    Command = taskRun,
                    Publisher = string.Empty,
                    IsKnown = IsKnownSystemPath(taskRun),
                    IsSuspicious = isSuspicious,
                    Classification = isSuspicious ? "Suspicious" : IsKnownSystemPath(taskRun) ? "Known" : "Unknown",
                    Severity = isSuspicious ? 6 : 2,
                    AuditedAtUtc = now
                });
            }
        }
        catch { }
    }

    private static void EnumerateAutoServices(List<AutostartEntry> results, DateTime now, CancellationToken ct)
    {
        try
        {
            foreach (var svc in ServiceController.GetServices())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    if (svc.StartType != ServiceStartMode.Automatic) continue;
                    var imagePath = GetServiceImagePath(svc.ServiceName);
                    if (string.IsNullOrEmpty(imagePath)) continue;
                    var isSuspicious = IsSuspiciousCommand(imagePath);
                    results.Add(new AutostartEntry
                    {
                        Id = Guid.NewGuid(),
                        Location = "AutoService",
                        EntryName = svc.ServiceName,
                        Command = imagePath,
                        Publisher = string.Empty,
                        IsKnown = IsKnownSystemPath(imagePath),
                        IsSuspicious = isSuspicious,
                        Classification = isSuspicious ? "Suspicious" : IsKnownSystemPath(imagePath) ? "Known" : "Unknown",
                        Severity = isSuspicious ? 6 : 1,
                        AuditedAtUtc = now
                    });
                }
                catch { }
                finally { svc.Dispose(); }
            }
        }
        catch { }
    }

    private static string GetServiceImagePath(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            return key?.GetValue("ImagePath")?.ToString() ?? string.Empty;
        }
        catch { return string.Empty; }
    }

    private static bool IsKnownSystemPath(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return false;
        var lower = cmd.ToLowerInvariant();
        return lower.Contains(@"windows\system32") || lower.Contains(@"windows\syswow64") ||
               lower.Contains(@"program files\") || lower.Contains(@"program files (x86)\");
    }

    private static bool IsSuspiciousCommand(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return false;
        var lower = cmd.ToLowerInvariant();
        return lower.Contains(@"c:\users\") || lower.Contains(@"c:\temp\") ||
               lower.Contains(@"c:\windows\temp") || lower.Contains("powershell -enc") ||
               lower.Contains("powershell -e ") || lower.Contains("cmd /c start") ||
               lower.Contains("mshta") || lower.Contains("wscript") || lower.Contains("regsvr32");
    }

    private static string[] SplitCsv(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool inQuote = false;
        foreach (var c in line)
        {
            if (c == '"') { inQuote = !inQuote; continue; }
            if (c == ',' && !inQuote) { result.Add(sb.ToString()); sb.Clear(); continue; }
            sb.Append(c);
        }
        result.Add(sb.ToString());
        return result.ToArray();
    }
}
