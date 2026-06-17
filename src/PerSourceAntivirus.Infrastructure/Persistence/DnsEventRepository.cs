using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class DnsEventRepository(AppDbContext dbContext) : IDnsEventRepository
{
    public async Task AddRangeAsync(IEnumerable<DnsQueryEvent> events, CancellationToken cancellationToken = default)
    {
        dbContext.DnsQueryEvents.AddRange(events);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<DnsQueryEvent>> GetAllAsync(bool onlySuspicious = false, CancellationToken cancellationToken = default)
    {
        var query = dbContext.DnsQueryEvents.AsNoTracking();
        if (onlySuspicious) query = query.Where(e => e.IsSuspicious);
        return await query.OrderByDescending(e => e.CapturedAtUtc).ToListAsync(cancellationToken);
    }
}
