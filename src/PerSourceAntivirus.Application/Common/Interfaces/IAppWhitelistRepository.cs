using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAppWhitelistRepository
{
    Task AddAsync(AppWhitelistEntry entry, CancellationToken ct = default);
    Task UpdateAsync(AppWhitelistEntry entry, CancellationToken ct = default);
    Task RemoveAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<AppWhitelistEntry>> GetAllAsync(CancellationToken ct = default);
}
