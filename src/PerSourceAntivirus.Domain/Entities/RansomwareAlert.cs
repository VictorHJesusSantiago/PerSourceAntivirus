using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Domain.Entities;

public class RansomwareAlert
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime DetectedAtUtc { get; set; } = DateTime.UtcNow;
    public RansomwareEventType EventType { get; set; }
    public RansomwareSeverity Severity { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public bool IsAcknowledged { get; set; }
}
