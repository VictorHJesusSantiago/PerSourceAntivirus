using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Diagnostics;

public sealed class DetectorDiagnostics(ILogger<DetectorDiagnostics> logger) : IDetectorDiagnostics
{
    private sealed class Counters
    {
        public long ScansCompleted;
        public long ScansFailed;
        public long AlertsRaised;
        public long LastSuccessTicks;
        public long LastFailureTicks;
        public string? LastFailureReason;
        public double LastScanDurationSeconds;
        public long ItemsInspected;
        public long ItemsSkipped;
    }

    private readonly ConcurrentDictionary<string, Counters> _counters = new(StringComparer.Ordinal);

    public void RecordScanCompleted(string detectorName, TimeSpan duration)
    {
        var c = _counters.GetOrAdd(detectorName, _ => new Counters());
        Interlocked.Increment(ref c.ScansCompleted);
        Interlocked.Exchange(ref c.LastSuccessTicks, DateTime.UtcNow.Ticks);
        c.LastScanDurationSeconds = duration.TotalSeconds;
    }

    public void RecordScanFailed(string detectorName, string reason, Exception? exception = null)
    {
        var c = _counters.GetOrAdd(detectorName, _ => new Counters());
        Interlocked.Increment(ref c.ScansFailed);
        Interlocked.Exchange(ref c.LastFailureTicks, DateTime.UtcNow.Ticks);
        c.LastFailureReason = reason;

        logger.LogDebug(exception, "Detector {Detector} scan failed: {Reason}", detectorName, reason);
    }

    public void RecordAlertRaised(string detectorName)
    {
        var c = _counters.GetOrAdd(detectorName, _ => new Counters());
        Interlocked.Increment(ref c.AlertsRaised);
    }

    public void RecordItemInspected(string detectorName)
        => Interlocked.Increment(ref _counters.GetOrAdd(detectorName, _ => new Counters()).ItemsInspected);

    public void RecordItemSkipped(string detectorName)
        => Interlocked.Increment(ref _counters.GetOrAdd(detectorName, _ => new Counters()).ItemsSkipped);

    public IReadOnlyList<DetectorHealth> GetHealthSnapshot() =>
        _counters
            .Select(kv => new DetectorHealth(
                kv.Key,
                Interlocked.Read(ref kv.Value.ScansCompleted),
                Interlocked.Read(ref kv.Value.ScansFailed),
                Interlocked.Read(ref kv.Value.AlertsRaised),
                TicksToUtc(Interlocked.Read(ref kv.Value.LastSuccessTicks)),
                TicksToUtc(Interlocked.Read(ref kv.Value.LastFailureTicks)),
                kv.Value.LastFailureReason,
                kv.Value.LastScanDurationSeconds,
                Interlocked.Read(ref kv.Value.ItemsInspected),
                Interlocked.Read(ref kv.Value.ItemsSkipped)))
            .OrderBy(h => h.DetectorName, StringComparer.Ordinal)
            .ToList();

    private static DateTime? TicksToUtc(long ticks) =>
        ticks == 0 ? null : new DateTime(ticks, DateTimeKind.Utc);
}
