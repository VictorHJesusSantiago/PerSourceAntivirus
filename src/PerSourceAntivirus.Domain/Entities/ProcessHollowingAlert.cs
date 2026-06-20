namespace PerSourceAntivirus.Domain.Entities;

public class ProcessHollowingAlert
{
    public Guid Id { get; set; }
    public required string TargetProcessName { get; set; }
    public int TargetProcessId { get; set; }
    public required string InjectorProcessName { get; set; }
    public int InjectorProcessId { get; set; }
    public required string DetectedSequence { get; set; } // comma-joined: "RWX_PrivateRegion,PeHeader,LargeRegion"
    public int StepsDetected { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
