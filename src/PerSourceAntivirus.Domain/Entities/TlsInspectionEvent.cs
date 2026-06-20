namespace PerSourceAntivirus.Domain.Entities;

public class TlsInspectionEvent
{
    public int Id { get; set; }
    public DateTime CapturedAtUtc { get; set; }
    public string TargetHost { get; set; } = string.Empty;
    public int TargetPort { get; set; }
    public string Method { get; set; } = string.Empty;
    public string RequestPath { get; set; } = string.Empty;
    public int ResponseStatus { get; set; }
    public bool IsSuspicious { get; set; }
    public string? SuspiciousReason { get; set; }
    public int RequestBodySize { get; set; }
    public int ResponseBodySize { get; set; }
}
