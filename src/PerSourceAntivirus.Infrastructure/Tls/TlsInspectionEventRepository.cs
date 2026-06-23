using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Tls;

public class TlsInspectionEventRepository(AppDbContext db) : ITlsInspectionEventRepository
{
    public async Task AddAsync(TlsInspectionEvent evt, CancellationToken ct = default)
    {
        db.Set<TlsInspectionEvent>().Add(evt);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<TlsInspectionEvent>> GetRecentAsync(int count = 100, CancellationToken ct = default)
        => await db.Set<TlsInspectionEvent>()
            .OrderByDescending(e => e.CapturedAtUtc)
            .Take(count)
            .ToListAsync(ct);
}
