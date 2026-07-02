namespace PerSourceAntivirus.Domain.Entities;

public class HostIsolationEvent
{
    public Guid Id { get; set; }
    public required string Action { get; set; } // Isolated | Restored
    public required string Reason { get; set; }
    public DateTime TriggeredAtUtc { get; set; }
}
