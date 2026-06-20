namespace PerSourceAntivirus.Domain.Entities;

public class WmiPersistenceAlert
{
    public int Id { get; set; }
    public DateTime DetectedAtUtc { get; set; }
    public string FilterName { get; set; } = string.Empty;
    public string ConsumerName { get; set; } = string.Empty;
    public string ConsumerType { get; set; } = string.Empty;
    public string QueryLanguage { get; set; } = string.Empty;
    public string Query { get; set; } = string.Empty;
    public string ScriptOrCommand { get; set; } = string.Empty;
    public string Severity { get; set; } = "High";
    public bool IsAcknowledged { get; set; }
}
