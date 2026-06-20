namespace PerSourceAntivirus.Domain.Entities;

public class BrowserCredentialAccessAlert
{
    public Guid Id { get; set; }
    public required string Browser { get; set; }
    public required string CredentialFilePath { get; set; }
    public required string AccessingProcess { get; set; }
    public int AccessingPid { get; set; }
    public bool WasBlocked { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
