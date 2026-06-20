namespace PerSourceAntivirus.Domain.Entities;

public class UserAccountAuditFinding
{
    public Guid Id { get; set; }
    public string AccountName { get; set; } = string.Empty;
    public string Issue { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
    public bool HasPassword { get; set; }
    public bool IsEnabled { get; set; }
    public bool PasswordNeverExpires { get; set; }
    public DateTime? LastLogon { get; set; }
    public string Classification { get; set; } = string.Empty;
    public int Severity { get; set; }
    public DateTime AuditedAtUtc { get; set; }
}
