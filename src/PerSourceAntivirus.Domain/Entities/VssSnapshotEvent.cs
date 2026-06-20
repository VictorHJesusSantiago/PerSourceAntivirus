namespace PerSourceAntivirus.Domain.Entities;

public class VssSnapshotEvent
{
    public Guid Id { get; set; }
    public string FolderPath { get; set; } = string.Empty;
    public string SnapshotId { get; set; } = string.Empty;
    public string SnapshotPath { get; set; } = string.Empty;
    public string TriggerReason { get; set; } = string.Empty;
    public bool IsRestoreAction { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
