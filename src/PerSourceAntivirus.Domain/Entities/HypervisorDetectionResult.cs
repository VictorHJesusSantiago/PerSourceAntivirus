namespace PerSourceAntivirus.Domain.Entities;

public class HypervisorDetectionResult
{
    public Guid Id { get; set; }
    public bool IsVirtualMachine { get; set; }
    public required string HypervisorType { get; set; }
    public required string DetectionMethods { get; set; }
    public required string CpuidLeaf { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
