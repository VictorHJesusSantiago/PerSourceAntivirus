namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPackerDetector
{
    Task<PackerDetectionResult> DetectAsync(string filePath, CancellationToken ct = default);
}

public record PackerDetectionResult(string PackerName, bool IsPacked, bool WasUnpacked, string? UnpackedFilePath);
