using PerSourceAntivirus.Domain.Enums;
namespace PerSourceAntivirus.Domain.Entities;
public class RootkitFinding
{
    public int Id { get; set; }
    public DateTime DetectedAtUtc { get; set; }
    public RootkitFindingType FindingType { get; set; }
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = "High";
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public bool IsAcknowledged { get; set; }
}
