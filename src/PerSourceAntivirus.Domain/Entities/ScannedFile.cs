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

    public List<YaraMatch> YaraMatches { get; set; } = [];

    public PeAnalysisResult? PeAnalysis { get; set; }

    public ScriptAnalysisResult? ScriptAnalysis { get; set; }

    public HashReputationResult? HashReputation { get; set; }

    public FileMetadataAnalysisResult? FileMetadata { get; set; }

    public OfficeMacroAnalysisResult? OfficeMacro { get; set; }

    public bool IsQuarantined { get; set; }

    public DateTime? QuarantinedAtUtc { get; set; }

    public string? QuarantinePath { get; set; }
}
