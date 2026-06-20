namespace PerSourceAntivirus.Domain.Entities;

public class CfgViolationAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ViolationAddress { get; set; }
    public required string ExceptionCode { get; set; }
    public required string Details { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
