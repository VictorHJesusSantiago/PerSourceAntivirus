using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Fileless;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IFilelessAlertRepository, FilelessAlertRepository>();
public class FilelessAlertRepository(AppDbContext db) : IFilelessAlertRepository
{
    public async Task AddAsync(FilelessAlert alert, CancellationToken ct = default)
    {
        db.Set<FilelessAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<FilelessAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<FilelessAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
