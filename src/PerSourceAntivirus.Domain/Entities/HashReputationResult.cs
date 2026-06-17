namespace PerSourceAntivirus.Domain.Entities;

public class HashReputationResult
{
    public Guid Id { get; set; }
    public Guid ScannedFileId { get; set; }
    public ScannedFile ScannedFile { get; set; } = null!;
    public int PositiveDetections { get; set; }
    public int TotalEngines { get; set; }
    public bool IsMalicious { get; set; }
    public string Source { get; set; } = string.Empty;
    public string? ReportUrl { get; set; }
    public DateTime CheckedAtUtc { get; set; }
}
