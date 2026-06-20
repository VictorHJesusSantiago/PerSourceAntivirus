namespace PerSourceAntivirus.Domain.Entities;

public class MbrWriteAttemptAlert
{
    public Guid Id { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public int DriveNumber { get; set; }
    public long Sector { get; set; }
    public bool WasBlocked { get; set; }
    public string DetectionMethod { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
