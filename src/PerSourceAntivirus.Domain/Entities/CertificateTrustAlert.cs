namespace PerSourceAntivirus.Domain.Entities;

public class CertificateTrustAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string FilePath { get; set; }
    public required string Thumbprint { get; set; }
    public required string SubjectName { get; set; }
    public required string Reason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
