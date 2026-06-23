using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Scanning;

public sealed class ScanProfileService(IScanProfileRepository repo) : IScanProfileService
{
    public Task<IReadOnlyList<ScanProfile>> GetAllAsync(CancellationToken ct = default)
        => repo.GetAllAsync(ct);

    public Task<ScanProfile?> GetDefaultAsync(CancellationToken ct = default)
        => repo.GetDefaultAsync(ct);

    public Task AddAsync(ScanProfile profile, CancellationToken ct = default)
        => repo.AddAsync(profile, ct);

    public Task UpdateAsync(ScanProfile profile, CancellationToken ct = default)
        => repo.UpdateAsync(profile, ct);

    public Task DeleteAsync(Guid id, CancellationToken ct = default)
        => repo.DeleteAsync(id, ct);
}
