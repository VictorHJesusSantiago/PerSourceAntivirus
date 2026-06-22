using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Privacy;

public sealed class ScreenLockerAlertRepository(AppDbContext db) : IScreenLockerAlertRepository
{
    public async Task AddAsync(ScreenLockerAlert alert, CancellationToken ct = default)
    {
        db.Set<ScreenLockerAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ScreenLockerAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ScreenLockerAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
