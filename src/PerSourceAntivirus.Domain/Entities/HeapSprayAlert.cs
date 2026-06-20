namespace PerSourceAntivirus.Domain.Entities;

public class HeapSprayAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public long TotalPrivateCommittedBytes { get; set; }
    public int SuspiciousRegionCount { get; set; }
    public double AverageRegionEntropy { get; set; } // Low entropy = repetitive = spray
    public required string SuspicionReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
