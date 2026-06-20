namespace PerSourceAntivirus.Domain.Entities;

public class PuaAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ImagePath { get; set; }
    public required string Category { get; set; } // Miner/RAT/Adware/Toolbar/Stalkerware
    public required string DetectionReason { get; set; }
    public required string DetectionDetails { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
