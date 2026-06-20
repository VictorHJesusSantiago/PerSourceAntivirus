namespace PerSourceAntivirus.Domain.Entities;

public class ReflectiveDllInjectionAlert
{
    public Guid Id { get; set; }
    public required string TargetProcessName { get; set; }
    public int TargetProcessId { get; set; }
    public ulong SuspiciousBaseAddress { get; set; }
    public long RegionSize { get; set; }
    public uint MemoryProtection { get; set; }
    public bool HasPeHeader { get; set; }
    public double RegionEntropy { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
