using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Signing;

public sealed class UnsignedBinaryAlertRepository(AppDbContext db) : IUnsignedBinaryAlertRepository
{
    public async Task AddAsync(UnsignedBinaryAlert alert, CancellationToken ct = default)
    {
        db.Set<UnsignedBinaryAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<UnsignedBinaryAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<UnsignedBinaryAlert>().ToListAsync(ct);
}
