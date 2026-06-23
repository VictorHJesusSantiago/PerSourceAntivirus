using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IProcessDoppelgangingAlertRepository, ProcessDoppelgangingAlertRepository>();
public sealed class ProcessDoppelgangingAlertRepository(AppDbContext db) : IProcessDoppelgangingAlertRepository
{
    public async Task AddAsync(ProcessDoppelgangingAlert alert, CancellationToken ct = default)
    {
        db.Set<ProcessDoppelgangingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ProcessDoppelgangingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ProcessDoppelgangingAlert>().ToListAsync(ct);
}
