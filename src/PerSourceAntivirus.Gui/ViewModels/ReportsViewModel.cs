using System.Diagnostics;
using System.IO;
using System.Windows.Input;
using System.Windows.Media;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Gui.ViewModels;

public sealed record ThreatTypeChartItem(string AlertType, int Count, double BarWidth);

public class ReportsViewModel : ViewModelBase
{
    private readonly IReportGenerator _reportGenerator;
    private readonly IThreatTrendService _trendService;
    private string _lastReportPath = string.Empty;
    private bool _isGenerating;

    public string LastReportPath { get => _lastReportPath; private set => Set(ref _lastReportPath, value); }
    public bool IsGenerating { get => _isGenerating; private set => Set(ref _isGenerating, value); }

    public ICommand GenerateWeeklyCommand { get; }
    public ICommand GenerateMonthlyCommand { get; }

    public ReportsViewModel(IReportGenerator reportGenerator, IThreatTrendService trendService)
    {
        _reportGenerator = reportGenerator;
        _trendService = trendService;
        GenerateWeeklyCommand  = new RelayCommand(async () => await GenerateWeeklyAsync());
        GenerateMonthlyCommand = new RelayCommand(async () => await GenerateMonthlyAsync());
        _ = LoadTrendsAsync();
    }

    private async Task GenerateWeeklyAsync()
    {
        if (IsGenerating) return;
        IsGenerating = true;
        try
        {
            var outputDir = Path.Combine(AppContext.BaseDirectory, "Reports");
            Directory.CreateDirectory(outputDir);
            var report = await _reportGenerator.GenerateWeeklyAsync(outputDir);
            LastReportPath = report.OutputFilePath;
            if (File.Exists(LastReportPath))
                Process.Start(new ProcessStartInfo(LastReportPath) { UseShellExecute = true });
        }
        catch { }
        finally { IsGenerating = false; }
    }

    private async Task GenerateMonthlyAsync()
    {
        if (IsGenerating) return;
        IsGenerating = true;
        try
        {
            var outputDir = Path.Combine(AppContext.BaseDirectory, "Reports");
            Directory.CreateDirectory(outputDir);
            var report = await _reportGenerator.GenerateMonthlyAsync(outputDir);
            LastReportPath = report.OutputFilePath;
            if (File.Exists(LastReportPath))
                Process.Start(new ProcessStartInfo(LastReportPath) { UseShellExecute = true });
        }
        catch { }
        finally { IsGenerating = false; }
    }

    private async Task LoadTrendsAsync()
    {
        try
        {
            var daily = await _trendService.GetDailyTrendAsync(30);
            var top   = await _trendService.GetTopThreatTypesAsync(10);

            DailyTrend = daily;
            TopTypes   = top;

            // Build bar chart items (max bar width = 380 px)
            var maxCount = top.Count > 0 ? top.Max(t => t.Count) : 1;
            if (maxCount == 0) maxCount = 1;
            ChartItems = top
                .Select(t => new ThreatTypeChartItem(t.AlertType, t.Count, t.Count * 380.0 / maxCount))
                .ToList();

            // Build trend polyline points (canvas 560 × 100)
            const double canvasW = 560, canvasH = 100;
            var maxAlerts = daily.Count > 0 ? daily.Max(d => d.AlertCount) : 1;
            if (maxAlerts == 0) maxAlerts = 1;
            var pts = new PointCollection();
            for (int i = 0; i < daily.Count; i++)
            {
                double x = daily.Count > 1 ? i * canvasW / (daily.Count - 1) : 0;
                double y = canvasH - daily[i].AlertCount * canvasH / maxAlerts;
                pts.Add(new System.Windows.Point(x, y));
            }
            pts.Freeze();
            TrendLinePoints = pts;

            // Build critical line
            var critPts = new PointCollection();
            for (int i = 0; i < daily.Count; i++)
            {
                double x = daily.Count > 1 ? i * canvasW / (daily.Count - 1) : 0;
                double y = canvasH - daily[i].CriticalCount * canvasH / maxAlerts;
                critPts.Add(new System.Windows.Point(x, y));
            }
            critPts.Freeze();
            CritLinePoints = critPts;

            Notify(nameof(DailyTrend));
            Notify(nameof(TopTypes));
            Notify(nameof(TotalThreatCount));
            Notify(nameof(ChartItems));
            Notify(nameof(TrendLinePoints));
            Notify(nameof(CritLinePoints));
        }
        catch { }
    }

    public IReadOnlyList<ThreatTrendPoint>    DailyTrend  { get; private set; } = [];
    public IReadOnlyList<ThreatTypeCount>    TopTypes    { get; private set; } = [];
    public IReadOnlyList<ThreatTypeChartItem> ChartItems { get; private set; } = [];
    public PointCollection TrendLinePoints { get; private set; } = new PointCollection();
    public PointCollection CritLinePoints  { get; private set; } = new PointCollection();
    public int TotalThreatCount => TopTypes.Sum(t => t.Count);
}
