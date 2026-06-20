namespace PerSourceAntivirus.Domain.Entities;

public class AlertTriage
{
    public Guid Id { get; set; }
    public required string AlertType { get; set; }
    public Guid AlertId { get; set; }
    public required string Status { get; set; } // Open/Investigating/FalsePositive/Resolved
    public int AutoSeverityScore { get; set; } // 1-10
    public required string Notes { get; set; }
    public required string TriagedBy { get; set; }
    public Guid? IncidentId { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? TriagedAtUtc { get; set; }
}
