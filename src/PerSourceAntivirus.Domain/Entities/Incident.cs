namespace PerSourceAntivirus.Domain.Entities;

public class Incident
{
    public Guid Id { get; set; }
    public required string Title { get; set; }
    public required string Description { get; set; }
    public int Severity { get; set; }
    public required string Status { get; set; } // Open/Investigating/Resolved/Closed
    public int AlertCount { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? ResolvedAtUtc { get; set; }
}
