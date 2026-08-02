using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

public sealed class ProcessGhostingAlertRepository(AppDbContext db) : IProcessGhostingAlertRepository
{
    public async Task AddAsync(ProcessGhostingAlert alert, CancellationToken ct = default)
    {
        db.Set<ProcessGhostingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ProcessGhostingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ProcessGhostingAlert>().ToListAsync(ct);
}
