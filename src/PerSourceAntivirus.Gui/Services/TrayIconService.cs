using System.Windows;
using System.Windows.Forms;
using PerSourceAntivirus.Gui.ViewModels;

namespace PerSourceAntivirus.Gui.Services;

public class TrayIconService(MainWindow window) : IDisposable
{
    private NotifyIcon? _trayIcon;

    public void Initialize()
    {
        _trayIcon = new NotifyIcon
        {
            Text = "PerSource Antivirus",
            Visible = true,
            Icon = SystemIcons.Shield,
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open PSAV", null, (_, _) => ShowWindow());
        menu.Items.Add("-");
        menu.Items.Add("Exit", null, (_, _) => System.Windows.Application.Current.Shutdown());

        _trayIcon.ContextMenuStrip = menu;
        _trayIcon.DoubleClick += (_, _) => ShowWindow();
    }

    public void ShowBalloon(string title, string message, ToolTipIcon icon = ToolTipIcon.Warning)
    {
        _trayIcon?.ShowBalloonTip(5000, title, message, icon);
    }

    private void ShowWindow()
    {
        window.Show();
        window.WindowState = WindowState.Normal;
        window.Activate();
    }

    public void Dispose()
    {
        _trayIcon?.Dispose();
    }
}
