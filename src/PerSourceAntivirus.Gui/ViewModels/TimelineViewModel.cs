using System.Collections.ObjectModel;
using System.Windows.Input;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Gui.ViewModels;

public class TimelineViewModel : ViewModelBase
{
    private readonly IAttackTimelineService _timelineService;
    private string _processIdInput = string.Empty;
    private string _status = string.Empty;
    private bool _isLoading;

    public string ProcessIdInput { get => _processIdInput; set => Set(ref _processIdInput, value); }
    public string Status { get => _status; private set => Set(ref _status, value); }
    public bool IsLoading { get => _isLoading; private set => Set(ref _isLoading, value); }

    public ObservableCollection<TimelineNode> Nodes { get; } = [];

    public ICommand LoadCommand { get; }

    public TimelineViewModel(IAttackTimelineService timelineService)
    {
        _timelineService = timelineService;
        LoadCommand = new RelayCommand(async () => await LoadAsync());
    }

    private async Task LoadAsync()
    {
        if (!int.TryParse(_processIdInput.Trim(), out int pid) || pid <= 0)
        {
            Status = "Informe um Process ID válido.";
            return;
        }

        IsLoading = true;
        Status = "Carregando...";
        Nodes.Clear();

        try
        {
            var from = DateTime.UtcNow.AddHours(-24);
            var to   = DateTime.UtcNow;
            var tl   = await _timelineService.GetTimelineAsync(pid, from, to);

            var root = new TimelineNode(
                $"[{tl.ProcessId}] {tl.ProcessName}  —  {tl.ImagePath}",
                "Process", null, null);

            foreach (var c in tl.ChildProcesses.OrderBy(x => x.CreatedAtUtc))
                root.Children.Add(new TimelineNode(
                    $"[{c.ProcessId}] {c.FileName}  {Truncate(c.CommandLine)}",
                    "ChildProcess", c.CreatedAtUtc,
                    c.IsSuspicious ? "#FF4A4A" : "#22A06B"));

            foreach (var f in tl.FileActivities.OrderBy(x => x.OccurredAtUtc))
                root.Children.Add(new TimelineNode(
                    $"{f.Operation}: {f.FileName}",
                    "FileActivity", f.OccurredAtUtc,
                    f.IsSuspicious ? "#FF4A4A" : "#555555"));

            foreach (var n in tl.NetworkConnections.OrderBy(x => x.CapturedAtUtc))
                root.Children.Add(new TimelineNode(
                    $"{n.Protocol}: {n.DestinationAddress}:{n.DestinationPort}",
                    "NetworkConnection", n.CapturedAtUtc,
                    n.IsBlocklisted ? "#FF4A4A" : "#5A7EFF"));

            foreach (var r in tl.RegistryActivities.OrderBy(x => x.OccurredAtUtc))
                root.Children.Add(new TimelineNode(
                    $"{r.Operation}: {r.KeyPath}\\{r.ValueName}",
                    "RegistryActivity", r.OccurredAtUtc,
                    r.IsSuspicious ? "#FF4A4A" : "#9B6DFF"));

            Nodes.Add(root);
            Status = $"PID {pid}: {root.Children.Count} eventos (últimas 24h).";
        }
        catch (Exception ex)
        {
            Status = $"Erro: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private static string Truncate(string s) =>
        s.Length > 70 ? s[..67] + "..." : s;
}

public class TimelineNode(string label, string eventType, DateTime? timestamp, string? color)
{
    public string Label { get; } = label;
    public string EventType { get; } = eventType;
    public DateTime? Timestamp { get; } = timestamp;
    public string Color { get; } = color ?? "#333333";
    public ObservableCollection<TimelineNode> Children { get; } = [];

    public string Icon => EventType switch
    {
        "Process"           => "⚙",
        "ChildProcess"      => "▶",
        "FileActivity"      => "📄",
        "NetworkConnection" => "🌐",
        "RegistryActivity"  => "🔑",
        _                   => "•"
    };

    public string Time => Timestamp.HasValue
        ? Timestamp.Value.ToLocalTime().ToString("HH:mm:ss.fff")
        : string.Empty;
}
