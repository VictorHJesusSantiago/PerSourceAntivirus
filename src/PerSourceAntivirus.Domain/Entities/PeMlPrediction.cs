namespace PerSourceAntivirus.Domain.Entities;

public class PeMlPrediction
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string FilePath { get; set; } = string.Empty;
    public float MaliciousProbability { get; set; }
    public string Classification { get; set; } = string.Empty;
    public string ModelVersion { get; set; } = string.Empty;
    public DateTime PredictedAtUtc { get; set; } = DateTime.UtcNow;
    public string? FeaturesJson { get; set; }
}
