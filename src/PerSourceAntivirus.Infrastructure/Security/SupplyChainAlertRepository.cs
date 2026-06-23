using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Security;

public sealed class SupplyChainAlertRepository(AppDbContext db) : ISupplyChainAlertRepository
{
    public async Task AddAsync(SupplyChainAlert alert, CancellationToken ct)
    {
        db.Set<SupplyChainAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<SupplyChainAlert>> GetAllAsync(CancellationToken ct)
        => await db.Set<SupplyChainAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
