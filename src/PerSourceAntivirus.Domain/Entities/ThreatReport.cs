namespace PerSourceAntivirus.Domain.Entities;

public class ThreatReport
{
    public Guid Id { get; set; }
    public required string ReportType { get; set; }
    public DateTime PeriodStart { get; set; }
    public DateTime PeriodEnd { get; set; }
    public required string OutputFilePath { get; set; }
    public int TotalFilesScanned { get; set; }
    public int TotalThreats { get; set; }
    public int TotalSuspicious { get; set; }
    public required string TopThreatTypes { get; set; }
    public DateTime GeneratedAtUtc { get; set; }
}
