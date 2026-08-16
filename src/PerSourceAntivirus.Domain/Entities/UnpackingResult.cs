namespace PerSourceAntivirus.Domain.Entities;

public class UnpackingResult
{
    public Guid Id { get; set; }
    public required string FilePath { get; set; }
    public required string DetectedPacker { get; set; }
    public bool IsPacked { get; set; }
    public bool WasUnpacked { get; set; }
    public string? UnpackedFilePath { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
