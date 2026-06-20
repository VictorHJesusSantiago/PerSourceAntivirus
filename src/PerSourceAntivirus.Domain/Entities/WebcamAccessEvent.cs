namespace PerSourceAntivirus.Domain.Entities;

public class WebcamAccessEvent
{
    public Guid Id { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string DevicePath { get; set; } = string.Empty;
    public string AccessType { get; set; } = string.Empty;
    public bool WasBlocked { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
