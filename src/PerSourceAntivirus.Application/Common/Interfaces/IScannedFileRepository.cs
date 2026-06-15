using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScannedFileRepository
{
    Task AddAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ScannedFile>> GetAllAsync(CancellationToken cancellationToken = default);
}
