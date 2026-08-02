using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class FullScreenDetector : IFullScreenDetector
{
    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    private static extern IntPtr GetDesktopWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetShellWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public uint cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    private const uint MONITOR_DEFAULTTONEAREST = 2;

    public bool IsFullScreenAppActive()
    {
        var hWnd = GetForegroundWindow();
        if (hWnd == IntPtr.Zero) return false;

        var shellWindow = GetShellWindow();
        var desktopWindow = GetDesktopWindow();
        if (hWnd == shellWindow || hWnd == desktopWindow) return false;
        if (GetWindowTextLength(hWnd) == 0) return false; // no titled window (e.g. taskbar) in foreground

        if (!GetWindowRect(hWnd, out var windowRect)) return false;

        var monitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
        if (monitor == IntPtr.Zero) return false;

        var info = new MONITORINFO { cbSize = (uint)Marshal.SizeOf<MONITORINFO>() };
        if (!GetMonitorInfo(monitor, ref info)) return false;

        return windowRect.Left <= info.rcMonitor.Left &&
               windowRect.Top <= info.rcMonitor.Top &&
               windowRect.Right >= info.rcMonitor.Right &&
               windowRect.Bottom >= info.rcMonitor.Bottom;
    }
}
