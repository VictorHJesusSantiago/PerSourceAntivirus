using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class WfpBlockRepository(AppDbContext db) : IWfpBlockRepository
{
    public async Task AddAsync(WfpBlock block, CancellationToken ct = default)
    {
        db.WfpBlocks.Add(block);
        await db.SaveChangesAsync(ct);
    }

    public async Task DeactivateAsync(string ipAddress, CancellationToken ct = default)
    {
        var blocks = await db.WfpBlocks
            .Where(b => b.IpAddress == ipAddress && b.IsActive)
            .ToListAsync(ct);
        foreach (var b in blocks) b.IsActive = false;
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<string>> GetActiveIpsAsync(CancellationToken ct = default)
        => await db.WfpBlocks
            .Where(b => b.IsActive)
            .Select(b => b.IpAddress)
            .Distinct()
            .ToListAsync(ct);

    public async Task<IReadOnlyList<WfpBlock>> GetAllAsync(CancellationToken ct = default)
        => await db.WfpBlocks.OrderByDescending(b => b.AddedAtUtc).ToListAsync(ct);
}
