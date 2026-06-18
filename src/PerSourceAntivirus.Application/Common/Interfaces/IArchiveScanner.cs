namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IArchiveScanner
{
    bool CanScan(string filePath);
    Task<ArchiveScanSummary> ScanAsync(string filePath, CancellationToken ct = default);
}

public record ArchiveScanSummary(
    int TotalEntries,
    int SuspiciousEntries,
    bool HasZipBomb,
    IReadOnlyList<string> SuspiciousEntryPaths);
