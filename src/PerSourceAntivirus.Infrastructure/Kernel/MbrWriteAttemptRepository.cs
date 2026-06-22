using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Kernel;

public sealed class MbrWriteAttemptRepository(AppDbContext db) : IMbrWriteAttemptRepository
{
    public async Task AddAsync(MbrWriteAttemptAlert alert, CancellationToken ct = default)
    {
        db.Set<MbrWriteAttemptAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<MbrWriteAttemptAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<MbrWriteAttemptAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
