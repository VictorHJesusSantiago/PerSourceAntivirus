using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Etw;

public sealed class ProcessCreationEventRepository(AppDbContext db) : IProcessCreationEventRepository
{
    public async Task AddAsync(ProcessCreationEvent evt, CancellationToken ct = default)
    {
        db.Set<ProcessCreationEvent>().Add(evt);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ProcessCreationEvent>> GetByProcessIdAsync(int pid, CancellationToken ct = default)
        => await db.Set<ProcessCreationEvent>()
            .Where(e => e.ProcessId == pid)
            .OrderByDescending(e => e.CreatedAtUtc)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<ProcessCreationEvent>> GetRecentAsync(int count = 1000, CancellationToken ct = default)
        => await db.Set<ProcessCreationEvent>()
            .OrderByDescending(e => e.CreatedAtUtc)
            .Take(count)
            .ToListAsync(ct);
}
