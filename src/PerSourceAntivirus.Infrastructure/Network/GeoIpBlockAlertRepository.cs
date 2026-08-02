using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class GeoIpBlockAlertRepository(AppDbContext db) : IGeoIpBlockAlertRepository
{
    public async Task AddAsync(GeoIpBlockAlert alert, CancellationToken ct = default)
    {
        db.Set<GeoIpBlockAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<GeoIpBlockAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<GeoIpBlockAlert>().ToListAsync(ct);
}
