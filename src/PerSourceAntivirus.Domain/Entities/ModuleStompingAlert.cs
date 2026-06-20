namespace PerSourceAntivirus.Domain.Entities;

public class ModuleStompingAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ModulePath { get; set; }
    public required string ModuleName { get; set; }
    public required string OnDiskHash { get; set; }   // SHA256 of on-disk .text section bytes
    public required string InMemoryHash { get; set; } // SHA256 of in-memory .text section bytes
    public long TextSectionSize { get; set; }
    public required string SuspicionReason { get; set; } // "TextSectionHashMismatch"
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
