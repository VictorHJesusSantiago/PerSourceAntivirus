namespace PerSourceAntivirus.Domain.Entities;

public class NetworkBehaviorAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string UnexpectedIp { get; set; }
    public int UnexpectedPort { get; set; }
    public required string AnomalyReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
