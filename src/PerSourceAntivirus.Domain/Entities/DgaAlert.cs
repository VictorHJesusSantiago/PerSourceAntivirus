namespace PerSourceAntivirus.Domain.Entities;

public class DgaAlert
{
    public Guid Id { get; set; }
    public required string Hostname { get; set; }
    public double EntropyScore { get; set; }
    public double ConsonantVowelRatio { get; set; }
    public int NxdomainStreak { get; set; }
    public double Probability { get; set; }
    public bool IsDga { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
