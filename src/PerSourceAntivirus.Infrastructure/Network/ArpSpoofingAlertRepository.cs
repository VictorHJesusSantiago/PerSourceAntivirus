using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class ArpSpoofingAlertRepository(AppDbContext db) : IArpSpoofingAlertRepository
{
    public async Task AddAsync(ArpSpoofingAlert alert, CancellationToken ct = default)
    {
        db.Set<ArpSpoofingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ArpSpoofingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ArpSpoofingAlert>().ToListAsync(ct);
}
