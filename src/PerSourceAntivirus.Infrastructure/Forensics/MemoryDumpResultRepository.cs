using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Forensics;

public sealed class MemoryDumpResultRepository(AppDbContext db) : IMemoryDumpResultRepository
{
    public async Task AddAsync(MemoryDumpResult result, CancellationToken ct)
    {
        db.Set<MemoryDumpResult>().Add(result);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<MemoryDumpResult>> GetAllAsync(CancellationToken ct)
        => await db.Set<MemoryDumpResult>().OrderByDescending(r => r.CreatedAtUtc).ToListAsync(ct);
}
