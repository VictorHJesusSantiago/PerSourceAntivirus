namespace PerSourceAntivirus.Domain.Entities;

public class ParentChildAnomalyAlert
{
    public Guid Id { get; set; }
    public required string ParentProcessName { get; set; }
    public int ParentProcessId { get; set; }
    public required string ChildProcessName { get; set; }
    public int ChildProcessId { get; set; }
    public required string ChildCommandLine { get; set; }
    public required string AnomalyReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
