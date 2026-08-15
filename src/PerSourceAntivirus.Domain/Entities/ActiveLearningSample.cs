namespace PerSourceAntivirus.Domain.Entities;

public class ActiveLearningSample
{
    public Guid Id { get; set; }
    public required string Sha256 { get; set; }
    public required string FeaturesJson { get; set; }
    public bool IsMalicious { get; set; }
    public DateTime RecordedAtUtc { get; set; }
}
