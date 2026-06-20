namespace PerSourceAntivirus.Domain.Entities;

public class AutostartEntry
{
    public Guid Id { get; set; }
    public string Location { get; set; } = string.Empty;
    public string EntryName { get; set; } = string.Empty;
    public string Command { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public bool IsKnown { get; set; }
    public bool IsSuspicious { get; set; }
    public string Classification { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime AuditedAtUtc { get; set; }
}
