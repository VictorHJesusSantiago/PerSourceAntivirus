namespace PerSourceAntivirus.Domain.Entities;

public class ProcessGhostingAlert
{
    public Guid Id { get; set; }
    public required string ProcessName { get; set; }
    public int ProcessId { get; set; }
    public required string ReportedImagePath { get; set; }
    public bool ImageFileExistsOnDisk { get; set; }
    public bool ImageFileAccessible { get; set; }
    public required string DetectionMethod { get; set; } // "FileNotFoundOnDisk","FilePendingDelete","HandleOpenedWithDeleteFlag"
    public int Severity { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
