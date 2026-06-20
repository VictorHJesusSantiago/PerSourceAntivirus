namespace PerSourceAntivirus.Domain.Entities;

public class ArpSpoofingAlert
{
    public Guid Id { get; set; }
    public required string AttackerMac { get; set; }
    public required string VictimIp { get; set; }
    public required string LegitimateKnownMac { get; set; }
    public required string SpoofedMac { get; set; }
    public required string DetectionReason { get; set; }  // "GratuitousArp","MacConflict","GatewayMacChanged","MultipleArpReplies"
    public int DuplicateCount { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
