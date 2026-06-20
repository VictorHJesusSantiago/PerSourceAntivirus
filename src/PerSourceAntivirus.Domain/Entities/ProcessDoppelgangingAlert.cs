namespace PerSourceAntivirus.Domain.Entities;

public class ProcessDoppelgangingAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ReportedImagePath { get; set; }
    public bool ImageExistsOnDisk { get; set; }
    public required string SuspicionReason { get; set; } // "ImageFileNotFound","TempPathImage","PathMismatch"
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
