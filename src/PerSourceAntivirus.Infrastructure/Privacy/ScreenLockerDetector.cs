using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Privacy;

[SupportedOSPlatform("windows")]
public sealed class ScreenLockerDetector : IScreenLockerDetector
{
    private readonly IScreenLockerAlertRepository _repository;
    private volatile bool _running;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DateTime> _recentAlerts = new();

    private static readonly HashSet<string> SystemProcessWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "winlogon", "LogonUI", "dwm", "csrss", "lsass",
        "svchost", "taskmgr", "SearchHost", "ShellExperienceHost",
        "StartMenuExperienceHost", "LockApp"
    };

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("user32.dll")]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern int GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    private const int SM_CXSCREEN = 0;
    private const int SM_CYSCREEN = 1;
    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TOPMOST = 0x8;
    private const uint WM_CLOSE = 0x0010;

    public event EventHandler<ScreenLockerAlertEventArgs>? AlertDetected;

    public ScreenLockerDetector(IScreenLockerAlertRepository repository)
    {
        _repository = repository;
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
                    CheckForegroundWindow();
                }
                catch { }
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private void CheckForegroundWindow()
    {
        var hwnd = GetForegroundWindow();
        if (hwnd == IntPtr.Zero)
            return;

        if (!GetWindowRect(hwnd, out var rect))
            return;

        var screenWidth = GetSystemMetrics(SM_CXSCREEN);
        var screenHeight = GetSystemMetrics(SM_CYSCREEN);

        var windowWidth = rect.Right - rect.Left;
        var windowHeight = rect.Bottom - rect.Top;

        var isFullscreen = windowWidth >= screenWidth && windowHeight >= screenHeight;
        if (!isFullscreen)
            return;

        var exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        var isTopmost = (exStyle & WS_EX_TOPMOST) != 0;

        if (!isTopmost)
            return;

        GetWindowThreadProcessId(hwnd, out var pid);
        if (pid == 0)
            return;

        SysProcess? proc = null;
        string processName;
        try
        {
            proc = SysProcess.GetProcessById(pid);
            processName = proc.ProcessName;
        }
        catch
        {
            return;
        }

        if (SystemProcessWhitelist.Contains(processName))
        {
            proc?.Dispose();
            return;
        }

        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(pid, out var last) && (now - last).TotalMinutes < 5)
        {
            proc?.Dispose();
            return;
        }
        _recentAlerts[pid] = now;

        var wasTerminated = false;

        try
        {
            PostMessage(hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
            Thread.Sleep(2000);

            try
            {
                proc.Refresh();
                if (!proc.HasExited)
                {
                    proc.Kill();
                    wasTerminated = true;
                }
                else
                {
                    wasTerminated = true;
                }
            }
            catch { wasTerminated = true; }
        }
        catch { }
        finally { proc?.Dispose(); }

        var alert = new ScreenLockerAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = processName,
            ProcessId = pid,
            DetectionMethod = "FullscreenTopmost",
            HasKeyboardHook = false,
            HasMouseHook = false,
            HasFullscreenWindow = true,
            WasTerminated = wasTerminated,
            Severity = 9,
            DetectedAtUtc = now
        };

        try { _repository.AddAsync(alert).GetAwaiter().GetResult(); } catch { }
        AlertDetected?.Invoke(this, new ScreenLockerAlertEventArgs(alert));
    }
}
