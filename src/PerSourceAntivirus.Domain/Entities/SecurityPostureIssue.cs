namespace PerSourceAntivirus.Domain.Entities;

public class SecurityPostureIssue
{
    public Guid Id { get; set; }
    public string CheckName { get; set; } = string.Empty;
    public string CurrentValue { get; set; } = string.Empty;
    public string ExpectedValue { get; set; } = string.Empty;
    public string IssueDescription { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime CheckedAtUtc { get; set; }
}
