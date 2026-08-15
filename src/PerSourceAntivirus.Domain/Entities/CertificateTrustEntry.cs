namespace PerSourceAntivirus.Domain.Entities;

public class CertificateTrustEntry
{
    public Guid Id { get; set; }
    public required string Thumbprint { get; set; }
    public required string SubjectName { get; set; }
    public required string TrustLevel { get; set; }
    public string? Note { get; set; }
    public DateTime AddedAtUtc { get; set; }
}
