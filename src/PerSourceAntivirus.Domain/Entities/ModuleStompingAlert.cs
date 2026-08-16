namespace PerSourceAntivirus.Domain.Entities;

public class ModuleStompingAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ModulePath { get; set; }
    public required string ModuleName { get; set; }
    public required string OnDiskHash { get; set; }
    public required string InMemoryHash { get; set; }
    public long TextSectionSize { get; set; }
    public required string SuspicionReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
