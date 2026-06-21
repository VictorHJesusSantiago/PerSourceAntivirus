using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

public sealed class ParentChildAnomalyAlertRepository(AppDbContext db) : IParentChildAnomalyAlertRepository
{
    public async Task AddAsync(ParentChildAnomalyAlert alert, CancellationToken ct)
    {
        db.Set<ParentChildAnomalyAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ParentChildAnomalyAlert>> GetAllAsync(CancellationToken ct)
        => await db.Set<ParentChildAnomalyAlert>()
            .OrderByDescending(a => a.DetectedAtUtc)
            .ToListAsync(ct);
}
