using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Uefi;

public class UefiFindingRepository(AppDbContext db) : IUefiFindingRepository
{
    public async Task AddRangeAsync(IEnumerable<UefiFinding> findings, CancellationToken ct = default)
    {
        db.Set<UefiFinding>().AddRange(findings);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<UefiFinding>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<UefiFinding>().OrderByDescending(f => f.DetectedAtUtc).ToListAsync(ct);
}
