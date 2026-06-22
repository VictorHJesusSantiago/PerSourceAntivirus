using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

public sealed class HeavensGateAlertRepository(AppDbContext db) : IHeavensGateAlertRepository
{
    public async Task AddAsync(HeavensGateAlert alert, CancellationToken ct = default)
    {
        db.Set<HeavensGateAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<HeavensGateAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<HeavensGateAlert>().ToListAsync(ct);
}
