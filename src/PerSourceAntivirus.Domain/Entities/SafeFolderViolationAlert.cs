namespace PerSourceAntivirus.Domain.Entities;

public class SafeFolderViolationAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ProtectedPath { get; set; }
    public required string AttemptedOperation { get; set; } // "Write","Delete","Rename","Overwrite"
    public bool WasBlocked { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
