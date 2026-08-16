namespace PerSourceAntivirus.Domain.Entities;

public class ResponsePlaybookRule
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public required string TriggerAlertType { get; set; }
    public int MinSeverity { get; set; }
    public required string Actions { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
