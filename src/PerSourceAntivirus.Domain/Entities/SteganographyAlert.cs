namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class SteganographyAlert
{
    public Guid Id { get; set; }
    public required string FilePath { get; set; }
    public double ChiSquareScore { get; set; }    // deviation from uniform LSB distribution
    public double HistogramAnomalyScore { get; set; }  // pairs of adjacent values with anomalous diff
    public double ChannelEntropy { get; set; }    // per-channel Shannon entropy (suspicious if too uniform, e.g., 7.99)
    public bool IsSuspicious { get; set; }
    public required string SuspicionReasons { get; set; }  // comma-joined
    public DateTime DetectedAtUtc { get; set; }
}
