using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class PortScanAlertRepository(AppDbContext db) : IPortScanAlertRepository
{
    public async Task AddAsync(PortScanAlert alert, CancellationToken ct = default)
    {
        db.Set<PortScanAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<PortScanAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<PortScanAlert>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
