namespace PerSourceAntivirus.Domain.Entities;

public class PeAnalysisResult
{
    public Guid Id { get; set; }

    public Guid ScannedFileId { get; set; }

    public ScannedFile? ScannedFile { get; set; }

    public bool Is64Bit { get; set; }

    public bool IsDll { get; set; }

    public bool IsDotNet { get; set; }

    public bool IsSigned { get; set; }

    public required string SuspiciousImports { get; set; }

    public required string Anomalies { get; set; }

    public List<PeSection> Sections { get; set; } = [];
}
