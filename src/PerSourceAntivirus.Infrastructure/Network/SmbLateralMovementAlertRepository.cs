using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class SmbLateralMovementAlertRepository(AppDbContext db) : ISmbLateralMovementAlertRepository
{
    public async Task AddAsync(SmbLateralMovementAlert alert, CancellationToken ct = default)
    {
        db.Set<SmbLateralMovementAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<SmbLateralMovementAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<SmbLateralMovementAlert>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
