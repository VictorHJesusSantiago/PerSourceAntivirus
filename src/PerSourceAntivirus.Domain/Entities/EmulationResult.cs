namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class EmulationResult
{
    public Guid Id { get; set; }
    public required string FilePath { get; set; }
    public int InstructionCount { get; set; }
    public int ApiCallsIntercepted { get; set; }
    public bool IsSuspicious { get; set; }
    public required string DetectedPatterns { get; set; }  // comma-joined
    public DateTime EmulatedAtUtc { get; set; }
}
