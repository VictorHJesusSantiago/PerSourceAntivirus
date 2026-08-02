namespace PerSourceAntivirus.Application.Common.Interfaces;

// Central health/telemetry sink for the real-time detectors (ADR-001).
//
// The problem it solves: detectors swallow exceptions on purpose — they run on ETW/WMI/pcap
// callback threads and inside loops that walk every process, where "access denied" is normal and
// letting an exception escape would kill the monitor. But swallowing them *silently* made a
// permanently-broken detector indistinguishable from a healthy one that simply found nothing.
//
// Every detector reports its scan outcomes here, so the app can answer "is this detector alive?"
// instead of inferring health from the absence of alerts.
public interface IDetectorDiagnostics
{
    void RecordScanCompleted(string detectorName, TimeSpan duration);
    void RecordScanFailed(string detectorName, string reason, Exception? exception = null);
    void RecordAlertRaised(string detectorName);

    IReadOnlyList<DetectorHealth> GetHealthSnapshot();
}

public record DetectorHealth(
    string DetectorName,
    long ScansCompleted,
    long ScansFailed,
    long AlertsRaised,
    DateTime? LastSuccessfulScanUtc,
    DateTime? LastFailureUtc,
    string? LastFailureReason,
    double LastScanDurationSeconds);
