namespace PerSourceAntivirus.Domain.Entities;

public class PlaybookExecutionLog
{
    public Guid Id { get; set; }
    public Guid RuleId { get; set; }
    public required string RuleName { get; set; }
    public required string AlertType { get; set; }
    public int Severity { get; set; }
    public int? ProcessId { get; set; }
    public string? FilePath { get; set; }
    public required string ActionsExecuted { get; set; }
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime ExecutedAtUtc { get; set; }
}
