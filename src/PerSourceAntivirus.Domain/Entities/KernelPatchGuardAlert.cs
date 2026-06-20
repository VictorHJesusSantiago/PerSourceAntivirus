namespace PerSourceAntivirus.Domain.Entities;

public class KernelPatchGuardAlert
{
    public Guid Id { get; set; }
    public required string BypassMethodType { get; set; }
    public required string Details { get; set; }
    public required string TargetFunction { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
