namespace PerSourceAntivirus.Domain.Entities;

public class DnsTunnelingAlert
{
    public Guid Id { get; set; }
    public required string SourceAddress { get; set; }
    public required string QueryDomain { get; set; }
    public int QueriesInWindow { get; set; }
    public double AverageLabelEntropy { get; set; }
    public double AverageQueryLength { get; set; }
    public required string DetectionReason { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
