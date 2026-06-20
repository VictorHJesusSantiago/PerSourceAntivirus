namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class EmailScanResult
{
    public Guid Id { get; set; }
    public Guid ScannedFileId { get; set; }
    public ScannedFile? ScannedFile { get; set; }
    public int AttachmentCount { get; set; }
    public int SuspiciousAttachmentCount { get; set; }
    public int PhishingLinkCount { get; set; }
    public required string SuspiciousAttachmentNames { get; set; }  // comma-joined
    public required string PhishingIndicators { get; set; }  // comma-joined
    public bool HasSpoofedSender { get; set; }
    public int RiskScore { get; set; }
    public DateTime ScannedAtUtc { get; set; }
}
