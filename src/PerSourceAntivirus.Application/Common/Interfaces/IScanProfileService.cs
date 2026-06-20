using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScanProfileService
{
    Task<IReadOnlyList<ScanProfile>> GetAllAsync(CancellationToken ct = default);
    Task<ScanProfile?> GetDefaultAsync(CancellationToken ct = default);
    Task AddAsync(ScanProfile profile, CancellationToken ct = default);
    Task UpdateAsync(ScanProfile profile, CancellationToken ct = default);
    Task DeleteAsync(Guid id, CancellationToken ct = default);
}
