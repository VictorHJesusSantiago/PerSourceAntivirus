namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class FilelessAlert
{
    public Guid Id { get; set; }
    public required string TechniqueType { get; set; }  // "PowerShellEncodedCommand", "WmiPersistence", "ProcessInjection", "RegistryAutoRun", etc.
    public required string Detail { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
