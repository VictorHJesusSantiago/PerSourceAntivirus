namespace PerSourceAntivirus.Domain.Entities;

public class AmsiScanEvent
{
    public Guid Id { get; set; }
    public required string ContentName { get; set; }
    public int AmsiResult { get; set; }
    public bool WasBlocked { get; set; }
    public DateTime ScannedAtUtc { get; set; }
}
