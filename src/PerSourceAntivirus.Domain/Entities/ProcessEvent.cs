namespace PerSourceAntivirus.Domain.Entities;

public class ProcessEvent
{
    public Guid Id { get; set; }
    public DateTime DetectedAtUtc { get; set; }
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ParentProcessId { get; set; }
    public string ParentProcessName { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
    public string? SuspicionReason { get; set; }
}
