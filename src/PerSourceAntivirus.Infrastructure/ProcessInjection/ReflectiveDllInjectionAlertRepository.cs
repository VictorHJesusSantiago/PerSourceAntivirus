using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IReflectiveDllInjectionAlertRepository, ReflectiveDllInjectionAlertRepository>();
public sealed class ReflectiveDllInjectionAlertRepository(AppDbContext db) : IReflectiveDllInjectionAlertRepository
{
    public async Task AddAsync(ReflectiveDllInjectionAlert alert, CancellationToken ct = default)
    {
        db.Set<ReflectiveDllInjectionAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ReflectiveDllInjectionAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ReflectiveDllInjectionAlert>().ToListAsync(ct);
}
