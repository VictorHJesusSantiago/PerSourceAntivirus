namespace PerSourceAntivirus.Domain.Entities;

public class LlmnrPoisoningAlert
{
    public Guid Id { get; set; }
    public required string Protocol { get; set; }         // "LLMNR","NBNS","MDNS"
    public required string QueryName { get; set; }
    public required string QuerierIp { get; set; }
    public required string ResponderIp { get; set; }
    public required string ResponderMac { get; set; }
    public required string SpoofedIp { get; set; }
    public required string DetectionReason { get; set; }  // "MultipleResponders","UnexpectedResponder","UnsolicitedResponse"
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
