namespace PerSourceAntivirus.Domain.Entities;

public class ApiCallSequenceAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ImagePath { get; set; }
    public required string ApiSequence { get; set; }
    public required string PatternName { get; set; }
    public required string DetectionReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
