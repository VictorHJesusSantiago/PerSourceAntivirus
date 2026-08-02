using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScannedFileRepository
{
    Task AddAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default);

    Task<ScannedFile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ScannedFile>> GetAllAsync(CancellationToken cancellationToken = default);

    Task UpdateAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<string, string>> GetExistingHashesAsync(IEnumerable<string> filePaths, CancellationToken cancellationToken = default);

    // Server-side count for the exclusion-impact preview — avoids loading every ScannedFile row
    // (plus its YaraMatches/PeAnalysis/ScriptAnalysis/HashReputation includes) into memory just
    // to count how many match a path/prefix.
    Task<(int totalMatches, int maliciousOrSuspiciousMatches)> CountByPathPrefixAsync(string pathOrPrefix, CancellationToken cancellationToken = default);
}
