using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Privacy;

[SupportedOSPlatform("windows")]
public sealed class ScreenCaptureDetector : IScreenCaptureDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private volatile bool _running;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DateTime> _recentAlerts = new();

    private static readonly HashSet<string> SystemProcessWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "dwm", "winlogon", "csrss", "lsass", "svchost",
        "taskmgr", "SearchHost", "ShellExperienceHost", "StartMenuExperienceHost",
        "ApplicationFrameHost", "RuntimeBroker", "sihost", "taskhostw",
        "fontdrvhost", "wlanext", "conhost", "dllhost", "msiexec",
        "WmiPrvSE", "spoolsv", "LsaIso", "SecurityHealthService",
        "MsMpEng", "NisSrv", "CompatTelRunner"
    };

    private static readonly HashSet<string> CaptureFunctions = new(StringComparer.OrdinalIgnoreCase)
    {
        "BitBlt", "StretchBlt", "PrintWindow"
    };

    public event EventHandler<ScreenCaptureAlertEventArgs>? AlertDetected;

    public ScreenCaptureDetector(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    // Per-write scope: AppDbContext is not thread-safe; alerts are raised from monitor threads.
    private async Task PersistAsync(ScreenCaptureAlert alert)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IScreenCaptureAlertRepository>();
            await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try
                {
                    ScanProcesses();
                }
                catch { }
                await Task.Delay(TimeSpan.FromSeconds(15), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private void ScanProcesses()
    {
        var processes = SysProcess.GetProcesses();
        foreach (var proc in processes)
        {
            try
            {
                ScanProcess(proc);
            }
            catch { }
            finally { proc.Dispose(); }
        }
    }

    private void ScanProcess(SysProcess proc)
    {
        if (SystemProcessWhitelist.Contains(proc.ProcessName))
            return;

        string mainModulePath;
        try
        {
            mainModulePath = proc.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            return;
        }

        if (string.IsNullOrEmpty(mainModulePath))
            return;

        if (IsSystemPath(mainModulePath))
            return;

        if (!HasScreenCaptureImports(mainModulePath, out var captureMethod))
            return;

        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(proc.Id, out var last) && (now - last).TotalMinutes < 30)
            return;
        _recentAlerts[proc.Id] = now;

        string windowTitle;
        try { windowTitle = proc.MainWindowTitle; } catch { windowTitle = string.Empty; }

        var alert = new ScreenCaptureAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = proc.ProcessName,
            ProcessId = proc.Id,
            TargetWindowTitle = windowTitle,
            CaptureMethod = captureMethod,
            WasBlocked = false,
            Severity = 5,
            DetectedAtUtc = now
        };

        _ = PersistAsync(alert);
        AlertDetected?.Invoke(this, new ScreenCaptureAlertEventArgs(alert));
    }

    private static bool IsSystemPath(string path)
        => path.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) ||
           path.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) ||
           path.Contains(@"\Windows\WinSxS\", StringComparison.OrdinalIgnoreCase);

    private static bool HasScreenCaptureImports(string modulePath, out string captureMethod)
    {
        captureMethod = string.Empty;
        try
        {
            using var fs = new FileStream(modulePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var data = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
            var read = fs.Read(data, 0, data.Length);
            if (read < 64)
                return false;

            if (data[0] != 0x4D || data[1] != 0x5A)
                return false;

            var content = System.Text.Encoding.ASCII.GetString(data, 0, read);

            foreach (var fn in CaptureFunctions)
            {
                if (content.Contains(fn, StringComparison.Ordinal))
                {
                    captureMethod = $"GDI-{fn}-Import";
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }
}
