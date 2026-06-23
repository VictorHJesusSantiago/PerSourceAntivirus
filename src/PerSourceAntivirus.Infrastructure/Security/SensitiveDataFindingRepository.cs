using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class SensitiveDataFindingRepository(AppDbContext db) : ISensitiveDataFindingRepository
{
    public async Task AddRangeAsync(IEnumerable<SensitiveDataFinding> items, CancellationToken ct = default)
    {
        db.Set<SensitiveDataFinding>().AddRange(items);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<SensitiveDataFinding>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<SensitiveDataFinding>().OrderByDescending(x => x.FoundAtUtc).ToListAsync(ct);
}
