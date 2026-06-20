namespace PerSourceAntivirus.Domain.Entities;

public class ScreenLockerAlert
{
    public Guid Id { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string DetectionMethod { get; set; } = string.Empty;
    public bool HasKeyboardHook { get; set; }
    public bool HasMouseHook { get; set; }
    public bool HasFullscreenWindow { get; set; }
    public bool WasTerminated { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
