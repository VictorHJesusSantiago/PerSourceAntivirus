using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class WpadAbuseAlertRepository(AppDbContext db) : IWpadAbuseAlertRepository
{
    public async Task AddAsync(WpadAbuseAlert alert, CancellationToken ct = default)
    {
        db.Set<WpadAbuseAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<WpadAbuseAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<WpadAbuseAlert>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
