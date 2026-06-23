using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Tls;

public sealed class TlsCertAlertRepository(AppDbContext db) : ITlsCertAlertRepository
{
    public async Task AddAsync(TlsCertAlert alert, CancellationToken ct = default)
    {
        db.Set<TlsCertAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<TlsCertAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<TlsCertAlert>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
