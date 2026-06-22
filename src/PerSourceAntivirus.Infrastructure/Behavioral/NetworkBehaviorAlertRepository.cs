using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

public sealed class NetworkBehaviorAlertRepository(AppDbContext db) : INetworkBehaviorAlertRepository
{
    public async Task AddAsync(NetworkBehaviorAlert alert, CancellationToken ct)
    {
        db.Set<NetworkBehaviorAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<NetworkBehaviorAlert>> GetAllAsync(CancellationToken ct)
        => await db.Set<NetworkBehaviorAlert>()
            .OrderByDescending(a => a.DetectedAtUtc)
            .ToListAsync(ct);
}
