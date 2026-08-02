using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Cryptojacking;

public sealed class CryptojackingAlertRepository(AppDbContext db) : ICryptojackingAlertRepository
{
    public async Task AddAsync(CryptojackingAlert alert, CancellationToken ct = default)
    {
        db.Set<CryptojackingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<CryptojackingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<CryptojackingAlert>().ToListAsync(ct);
}
