namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class PdfScanResult
{
    public Guid Id { get; set; }
    public Guid ScannedFileId { get; set; }
    public ScannedFile? ScannedFile { get; set; }
    public bool HasJavaScript { get; set; }
    public bool HasOpenAction { get; set; }
    public bool HasLaunchAction { get; set; }
    public bool HasRichMedia { get; set; }
    public bool HasXfa { get; set; }
    public bool HasEmbeddedFiles { get; set; }
    public bool HasObjStm { get; set; }
    public required string MaliciousObjectTypes { get; set; }  // comma-joined list
    public int RiskScore { get; set; }
    public DateTime ScannedAtUtc { get; set; }
}
