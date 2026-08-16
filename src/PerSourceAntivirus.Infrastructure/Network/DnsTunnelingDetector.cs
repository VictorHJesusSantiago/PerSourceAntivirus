using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class DnsTunnelingDetector : IDnsTunnelingDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IDnsMonitor _dnsMonitor;
    private readonly ConcurrentDictionary<string, Window> _windows = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;

    private const int WindowSeconds = 60;
    private const int MinQueriesForVolumeAlert = 40;
    private const double HighEntropyThreshold = 3.5;
    private const int LongLabelLength = 45;

    private sealed class Window
    {
        public readonly List<(DateTime at, string label, double entropy)> Entries = new();
        public readonly object Lock = new();
    }

    public event EventHandler<DnsTunnelingAlertEventArgs>? AlertDetected;

    public DnsTunnelingDetector(IServiceScopeFactory scopeFactory, IDnsMonitor dnsMonitor)
    {
        _scopeFactory = scopeFactory;
        _dnsMonitor = dnsMonitor;
    }

    private async Task PersistAsync(DnsTunnelingAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IDnsTunnelingAlertRepository>();
            await repository.AddAsync(alert, ct).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(string? deviceName, CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try
        {
            await foreach (var query in _dnsMonitor.WatchAsync(deviceName, _cts.Token).WithCancellation(_cts.Token))
            {
                try { await EvaluateAsync(query, _cts.Token); }
                catch (Exception) { }
            }
        }
        catch (OperationCanceledException) { }
    }

    public void StopMonitoring() => _cts?.Cancel();

    private async Task EvaluateAsync(DnsQueryData query, CancellationToken ct)
    {
        var domain = query.QueryName.Trim().TrimEnd('.');
        if (domain.Length == 0) return;

        var labels = domain.Split('.');
        if (labels.Length == 0) return;

        var subLabel = labels[0];
        var registeredDomain = labels.Length >= 2 ? string.Join('.', labels[^2..]) : domain;
        var entropy = CalculateEntropy(subLabel);
        var now = DateTime.UtcNow;
        var key = $"{query.SourceAddress}|{registeredDomain}";

        var window = _windows.GetOrAdd(key, _ => new Window());
        List<(DateTime at, string label, double entropy)> snapshot;
        lock (window.Lock)
        {
            window.Entries.Add((now, subLabel, entropy));
            window.Entries.RemoveAll(e => (now - e.at).TotalSeconds > WindowSeconds);
            snapshot = window.Entries.ToList();
        }

        if (snapshot.Count < 10) return;

        var avgEntropy = snapshot.Average(e => e.entropy);
        var avgLength = snapshot.Average(e => e.label.Length);
        var uniqueLabels = snapshot.Select(e => e.label).Distinct(StringComparer.OrdinalIgnoreCase).Count();

        string? reason = null;
        int severity = 0;

        if (snapshot.Count >= MinQueriesForVolumeAlert && uniqueLabels >= snapshot.Count * 0.9)
        {
            reason = "HighQueryVolume";
            severity = 7;
        }
        if (avgEntropy >= HighEntropyThreshold && avgLength >= 20)
        {
            reason = reason is null ? "HighEntropyLabels" : "HighEntropyLabels+HighQueryVolume";
            severity = 8;
        }
        else if (avgLength >= LongLabelLength)
        {
            reason ??= "LongQueryNames";
            severity = Math.Max(severity, 6);
        }

        if (reason is null) return;

        if (_alerted.TryGetValue(key, out var last) && (now - last).TotalMinutes < 15) return;
        _alerted[key] = now;

        var alert = new DnsTunnelingAlert
        {
            Id = Guid.NewGuid(),
            SourceAddress = query.SourceAddress,
            QueryDomain = registeredDomain,
            QueriesInWindow = snapshot.Count,
            AverageLabelEntropy = Math.Round(avgEntropy, 2),
            AverageQueryLength = Math.Round(avgLength, 1),
            DetectionReason = reason,
            Severity = severity,
            DetectedAtUtc = now
        };

        await PersistAsync(alert, ct).ConfigureAwait(false);
        AlertDetected?.Invoke(this, new DnsTunnelingAlertEventArgs(alert));
    }

    private static double CalculateEntropy(string label)
    {
        if (label.Length == 0) return 0;
        var freq = new Dictionary<char, int>();
        foreach (var c in label)
        {
            freq.TryGetValue(c, out var count);
            freq[c] = count + 1;
        }

        double entropy = 0;
        foreach (var count in freq.Values)
        {
            double p = (double)count / label.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
