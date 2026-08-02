using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class HostIsolationEventRepository(AppDbContext db) : IHostIsolationEventRepository
{
    public async Task AddAsync(HostIsolationEvent evt, CancellationToken ct = default)
    {
        db.Set<HostIsolationEvent>().Add(evt);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<HostIsolationEvent>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<HostIsolationEvent>().ToListAsync(ct);
}
