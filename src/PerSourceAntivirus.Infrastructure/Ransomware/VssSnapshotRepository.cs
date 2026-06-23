using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Ransomware;

public sealed class VssSnapshotRepository(AppDbContext db) : IVssSnapshotRepository
{
    public async Task AddAsync(VssSnapshotEvent snapshotEvent, CancellationToken ct = default)
    {
        db.Set<VssSnapshotEvent>().Add(snapshotEvent);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<VssSnapshotEvent>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<VssSnapshotEvent>().OrderByDescending(e => e.CreatedAtUtc).ToListAsync(ct);
}
