using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Domain.Entities;

public class ScannedFile
{
    public Guid Id { get; set; }

    public required string FilePath { get; set; }

    public required string FileName { get; set; }

    public long SizeBytes { get; set; }

    public required string Sha256Hash { get; set; }

    public double Entropy { get; set; }

    public DateTime ScannedAtUtc { get; set; }

    public ThreatStatus ThreatStatus { get; set; }
}
