namespace PerSourceAntivirus.Domain.Entities;

public class UnsignedBinaryAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string FilePath { get; set; }
    public bool IsSigned { get; set; }
    public bool IsTrusted { get; set; }
    public required string Reason { get; set; } // UnsignedInSuspiciousLocation | SignedButUntrusted
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
