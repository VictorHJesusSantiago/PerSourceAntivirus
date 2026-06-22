using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ComHijack;

public class ComHijackAlertRepository(AppDbContext db) : IComHijackAlertRepository
{
    public async Task AddAsync(ComHijackAlert alert, CancellationToken ct = default)
    {
        db.Set<ComHijackAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ComHijackAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ComHijackAlert>()
            .OrderByDescending(a => a.DetectedAtUtc)
            .ToListAsync(ct);
}
