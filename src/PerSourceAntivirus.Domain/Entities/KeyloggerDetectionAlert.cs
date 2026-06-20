namespace PerSourceAntivirus.Domain.Entities;

public class KeyloggerDetectionAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string DetectionMethod { get; set; }  // "WH_KEYBOARD_LL_Hook","KeyboardFilterDriver","RawInputSink","SuspiciousKeyboardDriver"
    public required string SuspiciousDetail { get; set; } // dll path, driver name, or description
    public required string ModulePath { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
