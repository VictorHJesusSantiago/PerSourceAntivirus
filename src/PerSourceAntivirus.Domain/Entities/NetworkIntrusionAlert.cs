namespace PerSourceAntivirus.Domain.Entities;

public class NetworkIntrusionAlert
{
    public Guid Id { get; set; }
    public required string SignatureName { get; set; }    // "EternalBlue","Log4Shell","Heartbleed","BlueKeep"
    public required string SourceIp { get; set; }
    public int SourcePort { get; set; }
    public required string DestinationIp { get; set; }
    public int DestinationPort { get; set; }
    public required string Protocol { get; set; }         // "TCP","UDP","SMB","HTTP"
    public required string MatchedPattern { get; set; }   // hex bytes that matched
    public int PayloadLength { get; set; }
    public required string Description { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
