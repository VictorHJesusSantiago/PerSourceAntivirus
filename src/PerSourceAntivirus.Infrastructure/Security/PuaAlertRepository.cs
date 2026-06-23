using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class PuaAlertRepository(AppDbContext db) : IPuaAlertRepository
{
    public async Task AddAsync(PuaAlert alert, CancellationToken ct = default)
    {
        db.Set<PuaAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<PuaAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<PuaAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
