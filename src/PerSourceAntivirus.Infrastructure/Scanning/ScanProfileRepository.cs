using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Scanning;

public sealed class ScanProfileRepository(AppDbContext db) : IScanProfileRepository
{
    public async Task AddAsync(ScanProfile profile, CancellationToken ct)
    {
        db.ScanProfiles.Add(profile);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(ScanProfile profile, CancellationToken ct)
    {
        db.ScanProfiles.Update(profile);
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct)
    {
        var profile = await db.ScanProfiles.FindAsync([id], ct);
        if (profile is not null)
        {
            db.ScanProfiles.Remove(profile);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<IReadOnlyList<ScanProfile>> GetAllAsync(CancellationToken ct)
        => await db.ScanProfiles
            .OrderBy(p => p.Name)
            .ToListAsync(ct);

    public async Task<ScanProfile?> GetDefaultAsync(CancellationToken ct)
        => await db.ScanProfiles
            .FirstOrDefaultAsync(p => p.IsDefault, ct);
}
