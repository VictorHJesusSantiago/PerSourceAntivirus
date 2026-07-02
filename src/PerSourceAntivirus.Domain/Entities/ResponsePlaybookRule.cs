namespace PerSourceAntivirus.Domain.Entities;

public class ResponsePlaybookRule
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public required string TriggerAlertType { get; set; } // e.g. "Ransomware", "ProcessHollowing", "*" for any
    public int MinSeverity { get; set; }
    public required string Actions { get; set; } // comma-separated: KillProcess,IsolateNetwork,Quarantine,Notify
    public bool IsEnabled { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
