using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScannedFileRepository
{
    Task AddAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default);

    Task<ScannedFile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ScannedFile>> GetAllAsync(CancellationToken cancellationToken = default);

    Task UpdateAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<string, string>> GetExistingHashesAsync(IEnumerable<string> filePaths, CancellationToken cancellationToken = default);
}
