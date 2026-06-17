namespace PerSourceAntivirus.Domain.Entities;

public class YaraMatch
{
    public Guid Id { get; set; }

    public Guid ScannedFileId { get; set; }

    public ScannedFile? ScannedFile { get; set; }

    public required string RuleIdentifier { get; set; }

    public required string Tags { get; set; }
}
