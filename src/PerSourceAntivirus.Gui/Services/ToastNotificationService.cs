using System.Windows.Forms;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Gui.Services;

// "Gamer mode": high-severity alerts (>= 8) always break through; everything else is
// suppressed while a fullscreen app (game, presentation, video) has focus.
public sealed class ToastNotificationService(IFullScreenDetector fullScreenDetector) : IToastNotificationService
{
    private NotifyIcon? _notifyIcon;
    private const int CriticalSeverityOverride = 8;

    public void ShowThreatDetected(string title, string message, string filePath)
    {
        if (fullScreenDetector.IsFullScreenAppActive()) return;
        ShowBalloon($"⚠️ {title}", $"{message}\n{filePath}", ToolTipIcon.Warning, 5000);
    }

    public void ShowAlert(string title, string message, int severity)
    {
        if (severity < CriticalSeverityOverride && fullScreenDetector.IsFullScreenAppActive()) return;
        ShowBalloon($"🛡 {title}", message, severity >= 8 ? ToolTipIcon.Error : ToolTipIcon.Warning, 4000);
    }

    public void ShowScanComplete(int totalScanned, int threats)
    {
        if (fullScreenDetector.IsFullScreenAppActive()) return;
        ShowBalloon("Scan Complete", $"Scanned {totalScanned} files. Threats: {threats}",
                       threats > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info, 3000);
    }

    private void ShowBalloon(string title, string text, ToolTipIcon icon, int timeout)
    {
        var ni = new NotifyIcon { Visible = true, Icon = SystemIcons.Shield };
        ni.ShowBalloonTip(timeout, title, text.Length > 200 ? text[..200] : text, icon);
        Task.Delay(timeout + 500).ContinueWith(_ => { ni.Visible = false; ni.Dispose(); });
    }
}
