namespace PerSourceAntivirus.Domain.Entities;

public class ProcessCreationEvent
{
    public Guid Id { get; set; }
    public required string ImagePath { get; set; }
    public required string FileName { get; set; }
    public required string CommandLine { get; set; }
    public required string Sha256Hash { get; set; }
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public required string ParentImagePath { get; set; }
    public required string UserName { get; set; }
    public required string IntegrityLevel { get; set; }
    public bool IsSuspicious { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
