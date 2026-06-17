namespace PerSourceAntivirus.Domain.Entities;

public class FileMetadataAnalysisResult
{
    public Guid Id { get; set; }
    public Guid ScannedFileId { get; set; }
    public ScannedFile ScannedFile { get; set; } = null!;
    public string? Author { get; set; }
    public string? Creator { get; set; }
    public DateTime? DocumentCreatedUtc { get; set; }
    public DateTime? DocumentModifiedUtc { get; set; }
    public bool HasEmbeddedFiles { get; set; }
    public bool HasJavaScript { get; set; }
    public bool IsPolyglot { get; set; }
    public string Anomalies { get; set; } = string.Empty;
}
