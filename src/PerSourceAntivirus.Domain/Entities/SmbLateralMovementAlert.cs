namespace PerSourceAntivirus.Domain.Entities;

public class SmbLateralMovementAlert
{
    public Guid Id { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public string TargetIp { get; set; } = string.Empty;
    public string DetectionReason { get; set; } = string.Empty;
    public string PipeName { get; set; } = string.Empty;
    public string ShareName { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
