using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

public sealed class NetworkBehaviorProfileRepository(AppDbContext db) : INetworkBehaviorProfileRepository
{
    public async Task AddOrUpdateAsync(NetworkBehaviorProfile profile, CancellationToken ct)
    {
        var existing = await db.Set<NetworkBehaviorProfile>()
            .FirstOrDefaultAsync(p => p.ProcessName == profile.ProcessName, ct);

        if (existing is null)
        {
            db.Set<NetworkBehaviorProfile>().Add(profile);
        }
        else
        {
            existing.BaselineIps = profile.BaselineIps;
            existing.BaselinePorts = profile.BaselinePorts;
            existing.ObservationCount = profile.ObservationCount;
            existing.LastUpdatedAtUtc = profile.LastUpdatedAtUtc;
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task<NetworkBehaviorProfile?> GetByProcessNameAsync(string processName, CancellationToken ct)
        => await db.Set<NetworkBehaviorProfile>()
            .FirstOrDefaultAsync(p => p.ProcessName == processName, ct);

    public async Task<IReadOnlyList<NetworkBehaviorProfile>> GetAllAsync(CancellationToken ct)
        => await db.Set<NetworkBehaviorProfile>()
            .OrderBy(p => p.ProcessName)
            .ToListAsync(ct);
}
