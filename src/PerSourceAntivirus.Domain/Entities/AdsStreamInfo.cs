namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class AdsStreamInfo
{
    public Guid Id { get; set; }
    public Guid ScannedFileId { get; set; }
    public ScannedFile? ScannedFile { get; set; }
    public required string StreamName { get; set; }
    public long StreamSize { get; set; }
    public bool IsSuspicious { get; set; }
    public required string Reason { get; set; }  // "HasExecutableContent", "HasPeHeader", "HasScript", "LargeHiddenData", "Clean"
}
