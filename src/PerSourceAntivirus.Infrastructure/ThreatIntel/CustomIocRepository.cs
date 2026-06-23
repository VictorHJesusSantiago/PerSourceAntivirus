using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ThreatIntel;

public sealed class CustomIocRepository(AppDbContext db) : ICustomIocRepository
{
    public async Task AddAsync(CustomIoc ioc, CancellationToken ct = default)
    {
        db.Set<CustomIoc>().Add(ioc);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<CustomIoc>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<CustomIoc>().Where(x => x.IsActive).ToListAsync(ct);

    public async Task RemoveAsync(Guid id, CancellationToken ct = default)
    {
        var item = await db.Set<CustomIoc>().FindAsync(new object[] { id }, ct);
        if (item != null)
        {
            db.Remove(item);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<IReadOnlyList<CustomIoc>> GetByTypeAsync(string type, CancellationToken ct = default)
        => await db.Set<CustomIoc>().Where(x => x.IsActive && x.IocType == type).ToListAsync(ct);
}
