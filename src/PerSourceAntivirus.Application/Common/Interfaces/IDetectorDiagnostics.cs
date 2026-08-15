namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDetectorDiagnostics
{
    void RecordScanCompleted(string detectorName, TimeSpan duration);
    void RecordScanFailed(string detectorName, string reason, Exception? exception = null);
    void RecordAlertRaised(string detectorName);

    void RecordItemInspected(string detectorName);
    void RecordItemSkipped(string detectorName);

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
    double LastScanDurationSeconds,
    long ItemsInspected = 0,
    long ItemsSkipped = 0);
