using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Rootkit;

public class RootkitFindingRepository(AppDbContext db) : IRootkitFindingRepository
{
    public async Task AddRangeAsync(IEnumerable<RootkitFinding> findings, CancellationToken ct = default)
    {
        db.Set<RootkitFinding>().AddRange(findings);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<RootkitFinding>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<RootkitFinding>().OrderByDescending(f => f.DetectedAtUtc).ToListAsync(ct);
}
