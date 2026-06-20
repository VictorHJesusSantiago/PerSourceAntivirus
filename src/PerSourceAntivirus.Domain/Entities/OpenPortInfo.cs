namespace PerSourceAntivirus.Domain.Entities;

public class OpenPortInfo
{
    public Guid Id { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public bool IsKnownRisk { get; set; }
    public string RiskDescription { get; set; } = string.Empty;
    public DateTime ScannedAtUtc { get; set; }
}
