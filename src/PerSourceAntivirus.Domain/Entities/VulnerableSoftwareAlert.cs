namespace PerSourceAntivirus.Domain.Entities;

public class VulnerableSoftwareAlert
{
    public Guid Id { get; set; }
    public string SoftwareName { get; set; } = string.Empty;
    public string SoftwareVersion { get; set; } = string.Empty;
    public string CpeUri { get; set; } = string.Empty;
    public string CveId { get; set; } = string.Empty;
    public double CvssScore { get; set; }
    public string CvssVector { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
