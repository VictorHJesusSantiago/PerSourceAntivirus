namespace PerSourceAntivirus.Domain.Entities;

public class TlsCertAlert
{
    public Guid Id { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public int Port { get; set; }
    public string SubjectCn { get; set; } = string.Empty;
    public string IssuerCn { get; set; } = string.Empty;
    public DateTime? CertExpiresUtc { get; set; }
    public bool IsSelfSigned { get; set; }
    public bool IsExpired { get; set; }
    public bool IsCnMismatch { get; set; }
    public bool IsUnknownCa { get; set; }
    public string ValidationError { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
