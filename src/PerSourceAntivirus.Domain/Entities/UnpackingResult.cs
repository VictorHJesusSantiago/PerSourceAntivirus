namespace PerSourceAntivirus.Domain.Entities;

// TODO: Add DbSet to AppDbContext
public class UnpackingResult
{
    public Guid Id { get; set; }
    public required string FilePath { get; set; }
    public required string DetectedPacker { get; set; }  // "None", "UPX", "MPRESS", "ASPack", "PECompact", "Themida", "VMProtect", "Unknown"
    public bool IsPacked { get; set; }
    public bool WasUnpacked { get; set; }
    public string? UnpackedFilePath { get; set; }
    public DateTime DetectedAtUtc { get; set; }
}
