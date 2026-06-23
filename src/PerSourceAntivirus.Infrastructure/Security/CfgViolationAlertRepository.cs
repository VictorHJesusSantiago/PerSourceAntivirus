using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class CfgViolationAlertRepository(AppDbContext db) : ICfgViolationAlertRepository
{
    public async Task AddAsync(CfgViolationAlert alert, CancellationToken ct = default)
    {
        db.Set<CfgViolationAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<CfgViolationAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<CfgViolationAlert>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
