namespace PerSourceAntivirus.Domain.Entities;

public class SupplyChainAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public required string FilePath { get; set; }
    public required string Publisher { get; set; }
    public required string CertificateThumbprint { get; set; }
    public required string AlertType { get; set; }
    public required string Details { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
