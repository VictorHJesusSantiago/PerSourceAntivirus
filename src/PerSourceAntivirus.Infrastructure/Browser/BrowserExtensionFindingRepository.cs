using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Browser;

public sealed class BrowserExtensionFindingRepository(AppDbContext db) : IBrowserExtensionFindingRepository
{
    public async Task AddRangeAsync(IEnumerable<BrowserExtensionFinding> findings, CancellationToken ct = default)
    {
        db.Set<BrowserExtensionFinding>().AddRange(findings);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<BrowserExtensionFinding>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<BrowserExtensionFinding>()
            .OrderByDescending(f => f.AuditedAtUtc)
            .ToListAsync(ct);
}
