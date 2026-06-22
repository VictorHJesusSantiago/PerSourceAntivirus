using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Kernel;

public sealed class SafeFolderViolationRepository(AppDbContext db) : ISafeFolderViolationRepository
{
    public async Task AddAsync(SafeFolderViolationAlert alert, CancellationToken ct = default)
    {
        db.Set<SafeFolderViolationAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<SafeFolderViolationAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<SafeFolderViolationAlert>().ToListAsync(ct);
}
