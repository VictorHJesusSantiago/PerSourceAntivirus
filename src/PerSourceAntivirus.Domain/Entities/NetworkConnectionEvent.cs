using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Domain.Entities;

public class NetworkConnectionEvent
{
    public Guid Id { get; set; }

    public DateTime CapturedAtUtc { get; set; }

    public NetworkProtocol Protocol { get; set; }

    public required string SourceAddress { get; set; }

    public int SourcePort { get; set; }

    public required string DestinationAddress { get; set; }

    public int DestinationPort { get; set; }

    public int PacketLength { get; set; }

    public bool IsBlocklisted { get; set; }

    public string? BlocklistReason { get; set; }
}
