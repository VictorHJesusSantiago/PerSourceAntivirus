using System.Windows.Threading;
using MediatR;
using PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Gui.ViewModels;

public class DashboardViewModel : ViewModelBase
{
    private readonly IMediator _mediator;
    private readonly DispatcherTimer _refreshTimer;

    private int _totalScanned;
    private int _threatCount;
    private int _suspiciousCount;
    private DateTime? _lastScanTime;
    private string _status = "Ready";
    private bool _isScanning;

    public int TotalScanned { get => _totalScanned; private set => Set(ref _totalScanned, value); }
    public int ThreatCount { get => _threatCount; private set => Set(ref _threatCount, value); }
    public int SuspiciousCount { get => _suspiciousCount; private set => Set(ref _suspiciousCount, value); }
    public DateTime? LastScanTime { get => _lastScanTime; private set => Set(ref _lastScanTime, value); }
    public string Status { get => _status; set => Set(ref _status, value); }
    public bool IsScanning { get => _isScanning; set => Set(ref _isScanning, value); }

    public string ProtectionStatus => ThreatCount > 0 ? "THREATS DETECTED" : "PROTECTED";
    public string ProtectionColor => ThreatCount > 0 ? "#FF4A4A" : "#4AFF8A";

    public DashboardViewModel(IMediator mediator)
    {
        _mediator = mediator;
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
        _refreshTimer.Start();
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var files = await _mediator.Send(new GetScannedFilesQuery());
            TotalScanned = files.Count;
            ThreatCount = files.Count(f => f.ThreatStatus == ThreatStatus.Malicious);
            SuspiciousCount = files.Count(f => f.ThreatStatus == ThreatStatus.Suspicious);
            LastScanTime = files.Count > 0 ? files.Max(f => f.ScannedAtUtc) : null;
            Notify(nameof(ProtectionStatus));
            Notify(nameof(ProtectionColor));
        }
        catch { /* non-fatal refresh failure */ }
    }
}
