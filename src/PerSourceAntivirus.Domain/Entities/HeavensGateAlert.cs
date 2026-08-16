namespace PerSourceAntivirus.Domain.Entities;

public class HeavensGateAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public ulong DetectedPatternAddress { get; set; }
    public required string PatternType { get; set; }
    public required string PatternBytes { get; set; }
    public bool IsWow64Process { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
