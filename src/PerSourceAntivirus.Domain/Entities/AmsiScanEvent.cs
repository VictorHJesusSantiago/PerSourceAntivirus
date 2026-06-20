namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class AmsiScanEvent
{
    public Guid Id { get; set; }
    public required string ContentName { get; set; }
    public int AmsiResult { get; set; }  // 0=Clean, 32768=Malware
    public bool WasBlocked { get; set; }
    public DateTime ScannedAtUtc { get; set; }
}
