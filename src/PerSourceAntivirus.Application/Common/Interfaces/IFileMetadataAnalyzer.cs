namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFileMetadataAnalyzer
{
    FileMetadataData? Analyze(string filePath);
}

public record FileMetadataData(
    string? Author,
    string? Creator,
    DateTime? DocumentCreatedUtc,
    DateTime? DocumentModifiedUtc,
    bool HasEmbeddedFiles,
    bool HasJavaScript,
    bool IsPolyglot,
    IReadOnlyList<string> Anomalies);
