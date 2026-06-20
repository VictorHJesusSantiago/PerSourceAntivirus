namespace PerSourceAntivirus.Domain.Entities;

public class ScanProfile
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public required string ProfileType { get; set; }
    public required string IncludePaths { get; set; }
    public required string ExcludePaths { get; set; }
    public required string FileExtensions { get; set; }
    public long MaxFileSizeBytes { get; set; }
    public bool IsDefault { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
