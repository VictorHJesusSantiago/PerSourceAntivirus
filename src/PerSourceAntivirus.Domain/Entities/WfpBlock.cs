namespace PerSourceAntivirus.Domain.Entities;

public class WfpBlock
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string IpAddress { get; set; } = string.Empty;
    public ulong FilterIdOutboundV4 { get; set; }
    public ulong FilterIdInboundV4 { get; set; }
    public string Reason { get; set; } = string.Empty;
    public DateTime AddedAtUtc { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
}
