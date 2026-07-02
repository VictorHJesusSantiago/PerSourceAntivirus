namespace PerSourceAntivirus.Domain.Entities;

public class ProcessFirewallRule
{
    public Guid Id { get; set; }
    public required string ProcessPath { get; set; }
    public required string Action { get; set; } // Block | Allow
    public string? Reason { get; set; }
    public DateTime AddedAtUtc { get; set; }
}
