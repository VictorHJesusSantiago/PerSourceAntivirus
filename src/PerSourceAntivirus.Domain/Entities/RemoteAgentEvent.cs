namespace PerSourceAntivirus.Domain.Entities;

public class RemoteAgentEvent
{
    public Guid Id { get; set; }
    public required string SourceHost { get; set; }
    public required string DeviceVendor { get; set; }
    public required string DeviceProduct { get; set; }
    public required string SignatureId { get; set; }
    public required string Name { get; set; }
    public int Severity { get; set; }
    public string? ExtensionsJson { get; set; }
    public DateTime ReceivedAtUtc { get; set; }
}
