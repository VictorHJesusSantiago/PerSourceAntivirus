using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Wmi;

public class WmiPersistenceAlertRepository(AppDbContext db) : IWmiPersistenceAlertRepository
{
    public async Task AddRangeAsync(IEnumerable<WmiPersistenceAlert> alerts, CancellationToken ct = default)
    {
        db.Set<WmiPersistenceAlert>().AddRange(alerts);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<WmiPersistenceAlert>> GetAllAsync(CancellationToken ct = default)
    {
        return await db.Set<WmiPersistenceAlert>()
            .OrderByDescending(a => a.DetectedAtUtc)
            .ToListAsync(ct);
    }
}
