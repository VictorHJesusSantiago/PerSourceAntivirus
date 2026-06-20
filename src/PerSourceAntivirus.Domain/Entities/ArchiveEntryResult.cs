namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class ArchiveEntryResult
{
    public Guid Id { get; set; }
    public Guid ArchiveScannedFileId { get; set; }
    public required string EntryPath { get; set; }
    public long EntrySize { get; set; }
    public int ScanDepth { get; set; }
    public bool IsSuspicious { get; set; }
    public required string DetectionReason { get; set; }
    public double Entropy { get; set; }
}
