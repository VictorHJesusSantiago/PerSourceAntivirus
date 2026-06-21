using System.Collections.ObjectModel;
using System.Windows.Threading;
using MediatR;
using PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Gui.ViewModels;

public class ThreatsViewModel : ViewModelBase
{
    private readonly IMediator _mediator;
    private readonly DispatcherTimer _refreshTimer;
    private string _filterText = string.Empty;

    public ObservableCollection<ThreatItem> Threats { get; } = [];

    public string FilterText
    {
        get => _filterText;
        set { Set(ref _filterText, value); _ = RefreshAsync(); }
    }

    public ThreatsViewModel(IMediator mediator)
    {
        _mediator = mediator;
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
        _refreshTimer.Start();
        _ = RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        try
        {
            var files = await _mediator.Send(new GetScannedFilesQuery());
            var filtered = files
                .Where(f => f.ThreatStatus is ThreatStatus.Malicious or ThreatStatus.Suspicious)
                .Where(f => string.IsNullOrEmpty(_filterText) ||
                            f.FileName.Contains(_filterText, StringComparison.OrdinalIgnoreCase) ||
                            f.FilePath.Contains(_filterText, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.ScannedAtUtc)
                .Select(f => new ThreatItem(
                    f.FileName, f.FilePath, f.ThreatStatus.ToString(),
                    f.ScannedAtUtc, f.Sha256Hash,
                    f.YaraMatches?.FirstOrDefault()?.RuleIdentifier ?? string.Empty))
                .ToList();

            Threats.Clear();
            foreach (var t in filtered) Threats.Add(t);
        }
        catch { /* non-fatal */ }
    }
}

public record ThreatItem(
    string FileName,
    string FilePath,
    string Status,
    DateTime DetectedAt,
    string Hash,
    string YaraRule)
{
    public string StatusColor => Status == "Malicious" ? "#FF4A4A" : "#FFB24A";
}
