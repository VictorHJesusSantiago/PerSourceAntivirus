namespace PerSourceAntivirus.Domain.Entities;

public class MitreAttackMapping
{
    public Guid Id { get; set; }
    public required string AlertType { get; set; }
    public required string TechniqueId { get; set; }
    public required string TechniqueName { get; set; }
    public required string Tactic { get; set; }
    public required string Description { get; set; }
    public required string MitreUrl { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
