namespace PerSourceAntivirus.Domain.Entities;

public class AlertTriage
{
    public Guid Id { get; set; }
    public required string AlertType { get; set; }
    public Guid AlertId { get; set; }
    public required string Status { get; set; }
    public int AutoSeverityScore { get; set; }
    public required string Notes { get; set; }
    public required string TriagedBy { get; set; }
    public Guid? IncidentId { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? TriagedAtUtc { get; set; }
}
