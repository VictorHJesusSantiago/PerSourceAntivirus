using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IAtomBombingAlertRepository, AtomBombingAlertRepository>();
public sealed class AtomBombingAlertRepository(AppDbContext db) : IAtomBombingAlertRepository
{
    public async Task AddAsync(AtomBombingAlert alert, CancellationToken ct = default)
    {
        db.Set<AtomBombingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AtomBombingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<AtomBombingAlert>().ToListAsync(ct);
}
