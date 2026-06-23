using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class AppWhitelistRepository(AppDbContext db) : IAppWhitelistRepository
{
    public async Task AddAsync(AppWhitelistEntry entry, CancellationToken ct = default)
    {
        db.Set<AppWhitelistEntry>().Add(entry);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(AppWhitelistEntry entry, CancellationToken ct = default)
    {
        db.Set<AppWhitelistEntry>().Update(entry);
        await db.SaveChangesAsync(ct);
    }

    public async Task RemoveAsync(Guid id, CancellationToken ct = default)
    {
        var entry = await db.Set<AppWhitelistEntry>().FindAsync([id], ct);
        if (entry != null)
        {
            db.Set<AppWhitelistEntry>().Remove(entry);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<IReadOnlyList<AppWhitelistEntry>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<AppWhitelistEntry>().OrderBy(e => e.EntryType).ThenBy(e => e.Value).ToListAsync(ct);
}
