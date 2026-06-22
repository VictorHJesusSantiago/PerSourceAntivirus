using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Investigation;

public sealed class IncidentRepository(AppDbContext db) : IIncidentRepository
{
    public async Task AddAsync(Incident incident, CancellationToken ct = default)
    {
        db.Set<Incident>().Add(incident);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(Incident incident, CancellationToken ct = default)
    {
        db.Set<Incident>().Update(incident);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<Incident>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<Incident>().OrderByDescending(i => i.CreatedAtUtc).ToListAsync(ct);

    public async Task<IReadOnlyList<Incident>> GetActiveAsync(CancellationToken ct = default)
        => await db.Set<Incident>()
            .Where(i => i.Status != "Resolved" && i.Status != "Closed")
            .OrderByDescending(i => i.CreatedAtUtc)
            .ToListAsync(ct);
}
