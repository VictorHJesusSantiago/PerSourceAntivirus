using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class NetworkConnectionEventRepository(AppDbContext dbContext) : INetworkConnectionEventRepository
{
    public async Task AddRangeAsync(IEnumerable<NetworkConnectionEvent> events, CancellationToken cancellationToken = default)
    {
        dbContext.NetworkConnectionEvents.AddRange(events);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<NetworkConnectionEvent>> GetAllAsync(bool onlyBlocklisted, CancellationToken cancellationToken = default)
    {
        var query = dbContext.NetworkConnectionEvents.AsNoTracking();

        if (onlyBlocklisted)
        {
            query = query.Where(e => e.IsBlocklisted);
        }

        return await query.OrderByDescending(e => e.CapturedAtUtc).ToListAsync(cancellationToken);
    }
}
