namespace PerSourceAntivirus.Domain.Entities;

public class CustomSignatureMatch
{
    public Guid Id { get; set; }
    public required string FilePath { get; set; }
    public required string FileHashSha256 { get; set; }
    public required string SignatureName { get; set; }
    public required string MatchType { get; set; } // Hash | Wildcard
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
