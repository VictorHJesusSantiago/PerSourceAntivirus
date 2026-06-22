using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IModuleStompingAlertRepository, ModuleStompingAlertRepository>();
public sealed class ModuleStompingAlertRepository(AppDbContext db) : IModuleStompingAlertRepository
{
    public async Task AddAsync(ModuleStompingAlert alert, CancellationToken ct = default)
    {
        db.Set<ModuleStompingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ModuleStompingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ModuleStompingAlert>().ToListAsync(ct);
}
