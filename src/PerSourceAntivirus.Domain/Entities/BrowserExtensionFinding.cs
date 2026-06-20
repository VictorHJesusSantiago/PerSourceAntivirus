namespace PerSourceAntivirus.Domain.Entities;

public class BrowserExtensionFinding
{
    public Guid Id { get; set; }
    public required string Browser { get; set; }
    public required string ExtensionId { get; set; }
    public required string ExtensionName { get; set; }
    public required string Version { get; set; }
    public required string Permissions { get; set; } // JSON array as string
    public bool IsSuspicious { get; set; }
    public required string RiskReason { get; set; }
    public int Severity { get; set; }
    public DateTime AuditedAtUtc { get; set; }
}
