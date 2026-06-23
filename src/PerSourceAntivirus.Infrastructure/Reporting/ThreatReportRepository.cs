using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Reporting;

public sealed class ThreatReportRepository(AppDbContext db) : IThreatReportRepository
{
    public async Task AddAsync(ThreatReport report, CancellationToken ct)
    {
        db.Set<ThreatReport>().Add(report);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ThreatReport>> GetAllAsync(CancellationToken ct)
        => await db.Set<ThreatReport>().OrderByDescending(r => r.GeneratedAtUtc).ToListAsync(ct);
}
