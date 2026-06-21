using System.Windows.Forms;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Gui.Services;

public sealed class ToastNotificationService : IToastNotificationService
{
    private NotifyIcon? _notifyIcon;

    public void ShowThreatDetected(string title, string message, string filePath)
        => ShowBalloon($"⚠️ {title}", $"{message}\n{filePath}", ToolTipIcon.Warning, 5000);

    public void ShowAlert(string title, string message, int severity)
        => ShowBalloon($"🛡 {title}", message, severity >= 8 ? ToolTipIcon.Error : ToolTipIcon.Warning, 4000);

    public void ShowScanComplete(int totalScanned, int threats)
        => ShowBalloon("Scan Complete", $"Scanned {totalScanned} files. Threats: {threats}",
                       threats > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info, 3000);

    private void ShowBalloon(string title, string text, ToolTipIcon icon, int timeout)
    {
        var ni = new NotifyIcon { Visible = true, Icon = SystemIcons.Shield };
        ni.ShowBalloonTip(timeout, title, text.Length > 200 ? text[..200] : text, icon);
        Task.Delay(timeout + 500).ContinueWith(_ => { ni.Visible = false; ni.Dispose(); });
    }
}
