using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Browser;

[SupportedOSPlatform("windows")]
public sealed class BrowserCredentialMonitor : IBrowserCredentialMonitor, IDisposable
{
    private readonly IBrowserCredentialAccessAlertRepository _repo;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly HashSet<string> _knownBrowserProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "iexplore", "opera", "brave", "vivaldi"
    };
    private bool _monitoring;
    private CancellationTokenSource? _cts;

    public event EventHandler<BrowserCredentialAccessAlertEventArgs>? AlertDetected;

    public BrowserCredentialMonitor(IBrowserCredentialAccessAlertRepository repo)
    {
        _repo = repo;
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        if (_monitoring) return;
        _monitoring = true;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var watchTargets = new List<(string FilePath, string Browser)>
        {
            (Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Login Data"), "Chrome"),
            (Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Login Data"), "Edge"),
        };

        var firefoxProfilesBase = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefoxProfilesBase))
        {
            foreach (var profileDir in Directory.EnumerateDirectories(firefoxProfilesBase))
            {
                watchTargets.Add((Path.Combine(profileDir, "logins.json"), "Firefox"));
                watchTargets.Add((Path.Combine(profileDir, "key4.db"), "Firefox"));
            }
        }

        foreach (var (filePath, browser) in watchTargets)
        {
            var dir = Path.GetDirectoryName(filePath);
            var fileName = Path.GetFileName(filePath);

            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

            try
            {
                var watcher = new FileSystemWatcher(dir, fileName)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.LastAccess,
                    EnableRaisingEvents = true
                };

                var capturedFilePath = filePath;
                var capturedBrowser = browser;

                watcher.Changed += (_, e) => HandleCredentialFileEvent(capturedFilePath, capturedBrowser, e.FullPath, _cts.Token);
                watcher.Created += (_, e) => HandleCredentialFileEvent(capturedFilePath, capturedBrowser, e.FullPath, _cts.Token);

                _watchers.Add(watcher);
            }
            catch { }
        }

        await Task.CompletedTask;
    }

    public void StopMonitoring()
    {
        _monitoring = false;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch { }
        }
        _watchers.Clear();
    }

    private void HandleCredentialFileEvent(string monitoredPath, string browser, string accessedPath, CancellationToken ct)
    {
        if (!string.Equals(monitoredPath, accessedPath, StringComparison.OrdinalIgnoreCase)) return;

        var accessingProcess = "Unknown";
        var accessingPid = 0;
        var isSuspicious = false;

        var browserProcs = SysProcess.GetProcesses()
            .Where(p => _knownBrowserProcessNames.Contains(p.ProcessName))
            .ToList();

        if (browserProcs.Count == 0)
        {
            isSuspicious = true;
        }
        else
        {
            var browserPids = new HashSet<int>(browserProcs.Select(p => p.Id));
            var allProcs = SysProcess.GetProcesses();
            var suspiciousProcs = allProcs
                .Where(p => !browserPids.Contains(p.Id) && !IsSystemProcess(p))
                .ToList();

            if (suspiciousProcs.Any())
            {
                isSuspicious = true;
                var firstSuspicious = suspiciousProcs.FirstOrDefault();
                if (firstSuspicious != null)
                {
                    accessingProcess = firstSuspicious.ProcessName;
                    accessingPid = firstSuspicious.Id;
                }
            }

            foreach (var p in browserProcs) { try { p.Dispose(); } catch { } }
            foreach (var p in allProcs) { try { p.Dispose(); } catch { } }
        }

        if (!isSuspicious) return;

        var alert = new BrowserCredentialAccessAlert
        {
            Id = Guid.NewGuid(),
            Browser = browser,
            CredentialFilePath = monitoredPath,
            AccessingProcess = accessingProcess,
            AccessingPid = accessingPid,
            WasBlocked = false,
            Severity = 9,
            DetectedAtUtc = DateTime.UtcNow
        };

        AlertDetected?.Invoke(this, new BrowserCredentialAccessAlertEventArgs(alert));

        _ = Task.Run(async () =>
        {
            try { await _repo.AddAsync(alert, ct); }
            catch { }
        }, ct);
    }

    private static bool IsSystemProcess(SysProcess process)
    {
        if (process.Id <= 4) return true;
        var name = process.ProcessName.ToLowerInvariant();
        return name is "system" or "smss" or "csrss" or "wininit" or "services" or "lsass" or "svchost";
    }

    public void Dispose()
    {
        StopMonitoring();
    }
}
