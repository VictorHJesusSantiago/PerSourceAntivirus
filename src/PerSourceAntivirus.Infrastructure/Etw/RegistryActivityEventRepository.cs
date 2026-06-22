using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Etw;

public sealed class RegistryActivityEventRepository(AppDbContext db) : IRegistryActivityEventRepository
{
    public async Task AddAsync(RegistryActivityEvent evt, CancellationToken ct = default)
    {
        db.Set<RegistryActivityEvent>().Add(evt);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RegistryActivityEvent>> GetByProcessIdAsync(int pid, CancellationToken ct = default)
        => await db.Set<RegistryActivityEvent>()
            .Where(e => e.ProcessId == pid)
            .OrderByDescending(e => e.OccurredAtUtc)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<RegistryActivityEvent>> GetByKeyPathAsync(string keyPath, CancellationToken ct = default)
        => await db.Set<RegistryActivityEvent>()
            .Where(e => e.KeyPath.Contains(keyPath))
            .OrderByDescending(e => e.OccurredAtUtc)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<RegistryActivityEvent>> GetRecentAsync(int count = 1000, CancellationToken ct = default)
        => await db.Set<RegistryActivityEvent>()
            .OrderByDescending(e => e.OccurredAtUtc)
            .Take(count)
            .ToListAsync(ct);
}
