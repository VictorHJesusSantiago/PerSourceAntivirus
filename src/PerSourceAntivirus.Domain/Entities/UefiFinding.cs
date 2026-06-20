namespace PerSourceAntivirus.Domain.Entities;
public class UefiFinding
{
    public int Id { get; set; }
    public DateTime DetectedAtUtc { get; set; }
    public string TableName { get; set; } = string.Empty;
    public string SignatureName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int MatchOffset { get; set; }
    public bool IsAcknowledged { get; set; }
}
