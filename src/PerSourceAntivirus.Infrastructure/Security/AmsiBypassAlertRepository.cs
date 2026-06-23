using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class AmsiBypassAlertRepository(AppDbContext db) : IAmsiBypassAlertRepository
{
    public async Task AddAsync(AmsiBypassAlert alert, CancellationToken ct = default)
    {
        db.Set<AmsiBypassAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AmsiBypassAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<AmsiBypassAlert>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
