using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ThreatIntel;

public sealed class StixFeedSourceRepository(AppDbContext db) : IStixFeedSourceRepository
{
    public async Task AddAsync(StixFeedSource source, CancellationToken ct = default)
    {
        db.Set<StixFeedSource>().Add(source);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(StixFeedSource source, CancellationToken ct = default)
    {
        db.Set<StixFeedSource>().Update(source);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<StixFeedSource>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<StixFeedSource>().ToListAsync(ct);
}
