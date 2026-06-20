namespace PerSourceAntivirus.Domain.Entities;

public class StixIoc
{
    public Guid Id { get; set; }
    public Guid FeedSourceId { get; set; }
    public required string IocType { get; set; }
    public required string Value { get; set; }
    public required string Labels { get; set; }
    public double Confidence { get; set; }
    public required string ThreatActors { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
