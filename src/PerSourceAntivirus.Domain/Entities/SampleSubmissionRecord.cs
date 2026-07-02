namespace PerSourceAntivirus.Domain.Entities;

public class SampleSubmissionRecord
{
    public Guid Id { get; set; }
    public required string OriginalFilePath { get; set; }
    public required string PackagedArchivePath { get; set; }
    public string? SubmittedToUrl { get; set; }
    public bool Submitted { get; set; }
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
