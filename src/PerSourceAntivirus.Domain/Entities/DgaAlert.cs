namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class DgaAlert
{
    public Guid Id { get; set; }
    public required string Hostname { get; set; }
    public double EntropyScore { get; set; }
    public double ConsonantVowelRatio { get; set; }
    public int NxdomainStreak { get; set; }
    public double Probability { get; set; }  // 0.0–1.0 DGA likelihood
    public bool IsDga { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
