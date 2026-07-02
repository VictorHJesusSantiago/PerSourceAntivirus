namespace PerSourceAntivirus.Domain.Entities;

public class AuditLogChainEntry
{
    public Guid Id { get; set; }
    public long SequenceNumber { get; set; }
    public required string EventDescription { get; set; }
    public required string PreviousHash { get; set; }
    public required string EntryHash { get; set; }
    public DateTime RecordedAtUtc { get; set; }
}
