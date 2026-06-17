namespace PerSourceAntivirus.Domain.Entities;

public class DnsQueryEvent
{
    public Guid Id { get; set; }
    public DateTime CapturedAtUtc { get; set; }
    public string QueryName { get; set; } = string.Empty;
    public string QueryType { get; set; } = string.Empty;
    public string SourceAddress { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
    public string? SuspicionReason { get; set; }
}
