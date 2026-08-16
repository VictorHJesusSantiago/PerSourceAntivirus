namespace PerSourceAntivirus.Domain.Entities;

public class NtdllUnhookingAlert
{
    public Guid Id { get; set; }
    public required string TargetProcessName { get; set; }
    public int TargetProcessId { get; set; }
    public int MappedNtdllCount { get; set; }
    public required string MappedPaths { get; set; }
    public required string SuspicionReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
