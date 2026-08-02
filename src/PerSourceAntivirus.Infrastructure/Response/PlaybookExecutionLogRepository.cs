using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Response;

public sealed class PlaybookExecutionLogRepository(AppDbContext db) : IPlaybookExecutionLogRepository
{
    public async Task AddAsync(PlaybookExecutionLog log, CancellationToken ct = default)
    {
        db.Set<PlaybookExecutionLog>().Add(log);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<PlaybookExecutionLog>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<PlaybookExecutionLog>().ToListAsync(ct);
}
