namespace PerSourceAntivirus.Domain.Entities;

public class RegistryActivityEvent
{
    public Guid Id { get; set; }
    public int ProcessId { get; set; }
    public required string ProcessName { get; set; }
    public required string KeyPath { get; set; }
    public required string ValueName { get; set; }
    public required string Operation { get; set; } // Create/Set/Delete
    public required string OldData { get; set; }
    public required string NewData { get; set; }
    public bool IsSuspicious { get; set; }
    public DateTime OccurredAtUtc { get; set; }
}
