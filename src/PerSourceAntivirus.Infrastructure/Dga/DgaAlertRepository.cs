using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Dga;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IDgaAlertRepository, DgaAlertRepository>();
public class DgaAlertRepository(AppDbContext db) : IDgaAlertRepository
{
    public async Task AddAsync(DgaAlert alert, CancellationToken ct = default)
    {
        db.Set<DgaAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<DgaAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<DgaAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
