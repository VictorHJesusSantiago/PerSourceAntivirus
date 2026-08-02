using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Uefi;

public sealed class SecureBootSnapshotRepository(AppDbContext db) : ISecureBootSnapshotRepository
{
    public async Task AddAsync(SecureBootStatusSnapshot snapshot, CancellationToken ct = default)
    {
        db.Set<SecureBootStatusSnapshot>().Add(snapshot);
        await db.SaveChangesAsync(ct);
    }

    public async Task<SecureBootStatusSnapshot?> GetLatestAsync(CancellationToken ct = default)
        => await db.Set<SecureBootStatusSnapshot>()
            .OrderByDescending(s => s.CheckedAtUtc)
            .FirstOrDefaultAsync(ct);

    public async Task<IReadOnlyList<SecureBootStatusSnapshot>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<SecureBootStatusSnapshot>().ToListAsync(ct);
}
