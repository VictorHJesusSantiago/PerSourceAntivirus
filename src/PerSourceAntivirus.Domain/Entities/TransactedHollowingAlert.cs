namespace PerSourceAntivirus.Domain.Entities;

public class TransactedHollowingAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string SuspiciousModulePath { get; set; }
    public bool ModuleFileExistsOnDisk { get; set; }
    public required string DetectionMethod { get; set; } // "ModuleFileNotOnDisk","TransactedPath","MappedSectionNoFile","ImageMappedPrivate"
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
