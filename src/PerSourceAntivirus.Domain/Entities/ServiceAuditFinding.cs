namespace PerSourceAntivirus.Domain.Entities;

public class ServiceAuditFinding
{
    public Guid Id { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public string ServiceDisplayName { get; set; } = string.Empty;
    public string BinaryPath { get; set; } = string.Empty;
    public bool IsUnquotedPath { get; set; }
    public bool IsWritablePath { get; set; }
    public bool IsSystemService { get; set; }
    public string FindingType { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime AuditedAtUtc { get; set; }
}
