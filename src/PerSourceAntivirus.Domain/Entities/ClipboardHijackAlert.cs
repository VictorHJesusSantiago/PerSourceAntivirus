namespace PerSourceAntivirus.Domain.Entities;

public class ClipboardHijackAlert
{
    public Guid Id { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string OriginalContent { get; set; } = string.Empty;
    public string SuspectedWalletAddress { get; set; } = string.Empty;
    public string AddressType { get; set; } = string.Empty;
    public bool WasBlocked { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
