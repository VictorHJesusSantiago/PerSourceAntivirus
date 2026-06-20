namespace PerSourceAntivirus.Domain.Entities;

public class WpadAbuseAlert
{
    public Guid Id { get; set; }
    public string QueryType { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string ResponderIp { get; set; } = string.Empty;
    public string WpadDatContent { get; set; } = string.Empty;
    public string DetectionReason { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
