using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class OpenPortInfoRepository(AppDbContext db) : IOpenPortInfoRepository
{
    public async Task AddRangeAsync(IEnumerable<OpenPortInfo> items, CancellationToken ct = default)
    {
        db.Set<OpenPortInfo>().AddRange(items);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<OpenPortInfo>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<OpenPortInfo>().OrderByDescending(x => x.ScannedAtUtc).ToListAsync(ct);
}
