namespace PerSourceAntivirus.Domain.Entities;

public class ProcessCommandLineAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string CommandLine { get; set; }
    public required string Triggers { get; set; }
    public int SuspicionScore { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
