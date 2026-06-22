using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class NetworkIntrusionAlertRepository(AppDbContext db) : INetworkIdsAlertRepository
{
    public async Task AddAsync(NetworkIntrusionAlert alert, CancellationToken ct = default)
    {
        db.Set<NetworkIntrusionAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<NetworkIntrusionAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<NetworkIntrusionAlert>().ToListAsync(ct);
}
