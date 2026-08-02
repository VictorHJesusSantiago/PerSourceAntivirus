using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class DnsTunnelingAlertRepository(AppDbContext db) : IDnsTunnelingAlertRepository
{
    public async Task AddAsync(DnsTunnelingAlert alert, CancellationToken ct = default)
    {
        db.Set<DnsTunnelingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<DnsTunnelingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<DnsTunnelingAlert>().ToListAsync(ct);
}
