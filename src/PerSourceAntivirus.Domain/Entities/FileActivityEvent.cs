namespace PerSourceAntivirus.Domain.Entities;

public class FileActivityEvent
{
    public Guid Id { get; set; }
    public int ProcessId { get; set; }
    public required string ProcessName { get; set; }
    public required string ImagePath { get; set; }
    public required string FilePath { get; set; }
    public required string FileName { get; set; }
    public required string Operation { get; set; } // Create/Write/Delete/Rename
    public long FileSize { get; set; }
    public required string Sha256Hash { get; set; }
    public bool IsSuspicious { get; set; }
    public DateTime OccurredAtUtc { get; set; }
}
