using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Pe;

public sealed class ActiveLearningSampleRepository(AppDbContext db) : IActiveLearningSampleRepository
{
    public async Task AddAsync(ActiveLearningSample sample, CancellationToken ct = default)
    {
        db.Set<ActiveLearningSample>().Add(sample);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ActiveLearningSample>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ActiveLearningSample>().ToListAsync(ct);

    public async Task<int> CountAsync(CancellationToken ct = default)
        => await db.Set<ActiveLearningSample>().CountAsync(ct);
}
