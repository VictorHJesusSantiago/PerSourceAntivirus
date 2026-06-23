using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IProcessHollowingAlertRepository, ProcessHollowingAlertRepository>();
public sealed class ProcessHollowingAlertRepository(AppDbContext db) : IProcessHollowingAlertRepository
{
    public async Task AddAsync(ProcessHollowingAlert alert, CancellationToken ct = default)
    {
        db.Set<ProcessHollowingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ProcessHollowingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ProcessHollowingAlert>().ToListAsync(ct);
}
