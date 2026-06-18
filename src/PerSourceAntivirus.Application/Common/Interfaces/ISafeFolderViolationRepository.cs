using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISafeFolderViolationRepository
{
    Task AddAsync(SafeFolderViolationAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<SafeFolderViolationAlert>> GetAllAsync(CancellationToken ct = default);
}
