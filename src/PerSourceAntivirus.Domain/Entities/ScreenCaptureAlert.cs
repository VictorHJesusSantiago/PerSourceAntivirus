namespace PerSourceAntivirus.Domain.Entities;

public class ScreenCaptureAlert
{
    public Guid Id { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string TargetWindowTitle { get; set; } = string.Empty;
    public string CaptureMethod { get; set; } = string.Empty;
    public bool WasBlocked { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
