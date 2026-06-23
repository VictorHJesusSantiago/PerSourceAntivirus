using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ThreatIntel;

public sealed class StixIocRepository(AppDbContext db) : IStixIocRepository
{
    public async Task AddRangeAsync(IEnumerable<StixIoc> iocs, CancellationToken ct = default)
    {
        db.Set<StixIoc>().AddRange(iocs);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<StixIoc>> GetByFeedAsync(Guid feedId, CancellationToken ct = default)
        => await db.Set<StixIoc>().Where(x => x.FeedSourceId == feedId).ToListAsync(ct);

    public async Task<IReadOnlyList<StixIoc>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<StixIoc>().ToListAsync(ct);
}
