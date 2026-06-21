using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Windows.Threading;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Gui.ViewModels;

public record AggregatedAlertItem(string AlertType, Guid AlertId, string Summary, int Severity, DateTime DetectedAt, string ProcessName)
{
    public string SeverityColor => Severity >= 8 ? "#FF4A4A" : Severity >= 5 ? "#FFB24A" : "#4AFF8A";
    public string SeverityLabel => Severity >= 8 ? "CRITICAL" : Severity >= 5 ? "HIGH" : "LOW";
    public string TruncatedSummary => Summary.Length > 80 ? Summary[..80] : Summary;
}

public class AlertsViewModel : ViewModelBase
{
    private readonly IAlertAggregatorService _aggregator;
    private readonly DispatcherTimer _refreshTimer;
    private string _filterText = string.Empty;
    private string _selectedType = "All";
    private List<AggregatedAlertItem> _allAlerts = [];

    public ObservableCollection<AggregatedAlertItem> Alerts { get; } = [];

    public string FilterText
    {
        get => _filterText;
        set { Set(ref _filterText, value); ApplyFilter(); }
    }

    public string SelectedType
    {
        get => _selectedType;
        set { Set(ref _selectedType, value); ApplyFilter(); }
    }

    public int TotalCount => Alerts.Count;

    public ICommand RefreshCommand { get; }

    public AlertsViewModel(IAlertAggregatorService aggregator)
    {
        _aggregator = aggregator;
        RefreshCommand = new RelayCommand(async () => await RefreshAsync());

        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
        _refreshTimer.Start();

        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            var alerts = await _aggregator.GetRecentAlertsAsync(200);
            _allAlerts = alerts
                .Select(a => new AggregatedAlertItem(a.AlertType, a.AlertId, a.Summary, a.Severity, a.DetectedAt, a.ProcessName))
                .ToList();
            ApplyFilter();
        }
        catch { }
    }

    private void ApplyFilter()
    {
        var filtered = _allAlerts.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(_filterText))
            filtered = filtered.Where(a =>
                a.Summary.Contains(_filterText, StringComparison.OrdinalIgnoreCase) ||
                a.ProcessName.Contains(_filterText, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrEmpty(_selectedType) && _selectedType != "All")
            filtered = filtered.Where(a => a.AlertType == _selectedType);

        Alerts.Clear();
        foreach (var item in filtered.OrderByDescending(a => a.DetectedAt))
            Alerts.Add(item);

        Notify(nameof(TotalCount));
    }
}
