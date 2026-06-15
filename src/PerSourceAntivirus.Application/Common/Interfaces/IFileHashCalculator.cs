namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFileHashCalculator
{
    Task<FileHashResult> ComputeAsync(string filePath, CancellationToken cancellationToken = default);
}

public record FileHashResult(string Sha256Hash, double Entropy, long SizeBytes);
