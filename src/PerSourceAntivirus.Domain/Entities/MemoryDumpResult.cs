namespace PerSourceAntivirus.Domain.Entities;

public class MemoryDumpResult
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string DumpFilePath { get; set; }
    public required string ExtractedStrings { get; set; }
    public required string ExtractedIps { get; set; }
    public required string ExtractedUrls { get; set; }
    public required string SuspiciousImports { get; set; }
    public int Severity { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
