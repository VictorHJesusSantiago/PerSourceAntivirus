using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScanProfileRepository
{
    Task AddAsync(ScanProfile profile, CancellationToken ct);
    Task UpdateAsync(ScanProfile profile, CancellationToken ct);
    Task DeleteAsync(Guid id, CancellationToken ct);
    Task<IReadOnlyList<ScanProfile>> GetAllAsync(CancellationToken ct);
    Task<ScanProfile?> GetDefaultAsync(CancellationToken ct);
}
