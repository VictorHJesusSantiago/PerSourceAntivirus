using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class AutostartEntryRepository(AppDbContext db) : IAutostartEntryRepository
{
    public async Task AddRangeAsync(IEnumerable<AutostartEntry> items, CancellationToken ct = default)
    {
        db.Set<AutostartEntry>().AddRange(items);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AutostartEntry>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<AutostartEntry>().OrderByDescending(x => x.AuditedAtUtc).ToListAsync(ct);
}
