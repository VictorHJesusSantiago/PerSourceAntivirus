using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.DllHijack;

public sealed class DllHijackAlertRepository(AppDbContext db) : IDllHijackAlertRepository
{
    public async Task AddAsync(DllHijackAlert alert, CancellationToken ct = default)
    {
        db.Set<DllHijackAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<DllHijackAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<DllHijackAlert>().ToListAsync(ct);
}
