using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class ScheduledScanRepository(AppDbContext dbContext) : IScheduledScanRepository
{
    public async Task AddAsync(ScheduledScan scan, CancellationToken cancellationToken = default)
    {
        dbContext.ScheduledScans.Add(scan);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ScheduledScan>> GetAllAsync(CancellationToken cancellationToken = default)
        => await dbContext.ScheduledScans.AsNoTracking().ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<ScheduledScan>> GetDueScansAsync(CancellationToken cancellationToken = default)
    {
        var all = await dbContext.ScheduledScans
            .Where(s => s.IsEnabled)
            .ToListAsync(cancellationToken);

        var now = DateTime.UtcNow;
        return all
            .Where(s => s.LastRunAtUtc is null ||
                        (now - s.LastRunAtUtc.Value).TotalMinutes >= s.IntervalMinutes)
            .ToList();
    }

    public async Task UpdateLastRunAsync(Guid id, DateTime lastRunAtUtc, CancellationToken cancellationToken = default)
    {
        var scan = await dbContext.ScheduledScans.FindAsync([id], cancellationToken);
        if (scan is not null)
        {
            scan.LastRunAtUtc = lastRunAtUtc;
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task RemoveAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var scan = await dbContext.ScheduledScans.FindAsync([id], cancellationToken);
        if (scan is not null)
        {
            dbContext.ScheduledScans.Remove(scan);
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }
}
