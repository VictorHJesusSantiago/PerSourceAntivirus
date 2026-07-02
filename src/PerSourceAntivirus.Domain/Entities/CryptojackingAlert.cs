namespace PerSourceAntivirus.Domain.Entities;

public class CryptojackingAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public double CpuPercent { get; set; }
    public string? RemoteAddress { get; set; }
    public int RemotePort { get; set; }
    public required string DetectionReason { get; set; } // SustainedHighCpu | MiningPoolPort | MiningPoolPortAndHighCpu
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
