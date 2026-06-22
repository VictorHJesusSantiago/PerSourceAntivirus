using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

public sealed class ProcessCommandLineAlertRepository(AppDbContext db) : IProcessCommandLineAlertRepository
{
    public async Task AddAsync(ProcessCommandLineAlert alert, CancellationToken ct)
    {
        db.Set<ProcessCommandLineAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ProcessCommandLineAlert>> GetAllAsync(CancellationToken ct)
        => await db.Set<ProcessCommandLineAlert>()
            .OrderByDescending(a => a.DetectedAtUtc)
            .ToListAsync(ct);
}
