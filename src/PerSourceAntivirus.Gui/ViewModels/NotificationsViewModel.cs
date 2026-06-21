using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Windows.Threading;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Gui.ViewModels;

public record NotificationItem(Guid Id, string Title, string Message, int Severity, string Status, DateTime CreatedAt)
{
    public string StatusColor => Status == "New" ? "#4AFF8A" : Status == "Acknowledged" ? "#FFB24A" : "#888888";
    public string SeverityColor => Severity >= 8 ? "#FF4A4A" : Severity >= 5 ? "#FFB24A" : "#4AFF8A";
}

public class NotificationsViewModel : ViewModelBase
{
    private readonly INotificationCenter _notificationCenter;
    private readonly DispatcherTimer _refreshTimer;
    private int _unreadCount;

    public ObservableCollection<NotificationItem> Notifications { get; } = [];

    public int UnreadCount
    {
        get => _unreadCount;
        private set => Set(ref _unreadCount, value);
    }

    public ICommand AcknowledgeCommand { get; }
    public ICommand AcknowledgeAllCommand { get; }

    public NotificationsViewModel(INotificationCenter notificationCenter)
    {
        _notificationCenter = notificationCenter;

        AcknowledgeCommand = new RelayCommand<Guid>(async id => await AcknowledgeAsync(id));
        AcknowledgeAllCommand = new RelayCommand(async () => await AcknowledgeAllAsync());

        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
        _refreshTimer.Start();

        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            var records = await _notificationCenter.GetRecentAsync(100);
            Notifications.Clear();
            foreach (var r in records)
                Notifications.Add(new NotificationItem(r.Id, r.Title, r.Message, r.Severity, r.Status, r.CreatedAtUtc));

            UnreadCount = await _notificationCenter.GetUnreadCountAsync();
        }
        catch { }
    }

    private async Task AcknowledgeAsync(Guid id)
    {
        try
        {
            await _notificationCenter.AcknowledgeAsync(id);
            await RefreshAsync();
        }
        catch { }
    }

    private async Task AcknowledgeAllAsync()
    {
        try
        {
            var pending = Notifications.Where(n => n.Status == "New").Select(n => n.Id).ToList();
            foreach (var id in pending)
                await _notificationCenter.AcknowledgeAsync(id);
            await RefreshAsync();
        }
        catch { }
    }
}

public class RelayCommand<T>(Func<T, Task> execute) : System.Windows.Input.ICommand
{
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter)
    {
        if (parameter is T value)
            _ = execute(value);
    }
}
