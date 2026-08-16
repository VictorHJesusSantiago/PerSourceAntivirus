namespace PerSourceAntivirus.Domain.Entities;

public class SteganographyAlert
{
    public Guid Id { get; set; }
    public required string FilePath { get; set; }
    public double ChiSquareScore { get; set; }
    public double HistogramAnomalyScore { get; set; }
    public double ChannelEntropy { get; set; }
    public bool IsSuspicious { get; set; }
    public required string SuspicionReasons { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
