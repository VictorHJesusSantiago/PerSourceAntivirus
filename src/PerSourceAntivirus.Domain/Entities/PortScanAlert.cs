namespace PerSourceAntivirus.Domain.Entities;

public class PortScanAlert
{
    public Guid Id { get; set; }
    public string SourceIp { get; set; } = string.Empty;
    public string TargetPorts { get; set; } = string.Empty;
    public int ConnectionCount { get; set; }
    public double TimeWindowMs { get; set; }
    public string DetectionMethod { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
