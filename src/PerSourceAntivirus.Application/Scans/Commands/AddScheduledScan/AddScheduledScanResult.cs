namespace PerSourceAntivirus.Application.Scans.Commands.AddScheduledScan;

public record AddScheduledScanResult(Guid Id, string Path, int IntervalMinutes);
