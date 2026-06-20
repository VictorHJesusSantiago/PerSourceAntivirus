namespace PerSourceAntivirus.Domain.Entities;

public class BeaconingAnalysis
{
    public Guid Id { get; set; }
    public string DestinationIp { get; set; } = string.Empty;
    public int DestinationPort { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public double AverageIntervalSeconds { get; set; }
    public double JitterVariance { get; set; }
    public double PayloadSizeVariance { get; set; }
    public int SampleCount { get; set; }
    public bool IsOutsideBusinessHours { get; set; }
    public int BeaconingScore { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
