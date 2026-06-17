using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class ProcessEventRepository(AppDbContext dbContext) : IProcessEventRepository
{
    public async Task AddRangeAsync(IEnumerable<ProcessEvent> events, CancellationToken cancellationToken = default)
    {
        dbContext.ProcessEvents.AddRange(events);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ProcessEvent>> GetAllAsync(bool onlySuspicious = false, CancellationToken cancellationToken = default)
    {
        var query = dbContext.ProcessEvents.AsNoTracking();
        if (onlySuspicious) query = query.Where(e => e.IsSuspicious);
        return await query.OrderByDescending(e => e.DetectedAtUtc).ToListAsync(cancellationToken);
    }
}
