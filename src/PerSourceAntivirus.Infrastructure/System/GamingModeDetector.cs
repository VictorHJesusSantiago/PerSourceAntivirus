using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class GamingModeDetector : IGamingModeDetector, IDisposable
{
    private static readonly HashSet<string> KnownGameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam", "epicgameslauncher", "battle.net", "riotclientservices", "leagueclientux",
        "gta5", "csgo", "minecraft.windows", "valorant", "overwatch", "fortnite",
        "witcher3", "cyberpunk2077", "elden_ring", "doom"
    };

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    private const int SM_CXSCREEN = 0;
    private const int SM_CYSCREEN = 1;
    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TOPMOST = 0x00000008;

    private volatile bool _isGamingModeActive;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    public bool IsGamingModeActive => _isGamingModeActive;

    public event EventHandler<bool>? GamingModeChanged;

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
                var gaming = DetectGamingMode();

                if (gaming != _isGamingModeActive)
                {
                    _isGamingModeActive = gaming;
                    GamingModeChanged?.Invoke(this, gaming);
                }
            }
            catch { }

            try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private static bool DetectGamingMode()
    {
        if (IsFullscreenTopmostWindow())
            return true;

        if (HasKnownGameProcess())
            return true;

        if (IsGameBarRunning())
            return true;

        return false;
    }

    private static bool IsFullscreenTopmostWindow()
    {
        try
        {
            var hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero)
                return false;

            if (!GetWindowRect(hwnd, out var rect))
                return false;

            var screenW = GetSystemMetrics(SM_CXSCREEN);
            var screenH = GetSystemMetrics(SM_CYSCREEN);

            var isFullscreen = rect.Left == 0 && rect.Top == 0 &&
                               rect.Right == screenW && rect.Bottom == screenH;

            if (!isFullscreen)
                return false;

            var exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
            return (exStyle & WS_EX_TOPMOST) != 0;
        }
        catch { return false; }
    }

    private static bool HasKnownGameProcess()
    {
        try
        {
            foreach (var proc in SysProcess.GetProcesses())
            {
                try
                {
                    if (KnownGameProcesses.Contains(proc.ProcessName))
                    {
                        proc.Dispose();
                        return true;
                    }
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }
        catch { }
        return false;
    }

    private static bool IsGameBarRunning()
    {
        try
        {
            foreach (var proc in SysProcess.GetProcesses())
            {
                try
                {
                    if (proc.ProcessName.Contains("GameBar", StringComparison.OrdinalIgnoreCase))
                    {
                        proc.Dispose();
                        return true;
                    }
                }
                catch { }
                finally
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }
        catch { }
        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts?.Cancel();
        _cts?.Dispose();
    }
}
