namespace PerSourceAntivirus.Domain.Entities;

public class KeyloggerDetectionAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string DetectionMethod { get; set; }
    public required string SuspiciousDetail { get; set; }
    public required string ModulePath { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
