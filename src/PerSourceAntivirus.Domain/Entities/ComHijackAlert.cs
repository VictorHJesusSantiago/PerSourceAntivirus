namespace PerSourceAntivirus.Domain.Entities;

public class ComHijackAlert
{
    public int Id { get; set; }
    public DateTime DetectedAtUtc { get; set; }
    public string AlertType { get; set; } = string.Empty;
    public string ClsidOrPath { get; set; } = string.Empty;
    public string SuspiciousPath { get; set; } = string.Empty;
    public string? LegitimateSystemPath { get; set; }
    public string Severity { get; set; } = "High";
    public bool IsAcknowledged { get; set; }
}
