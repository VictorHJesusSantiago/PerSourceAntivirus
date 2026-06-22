using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.LolBin;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<ILolBinAlertRepository, LolBinAlertRepository>();
public class LolBinAlertRepository(AppDbContext db) : ILolBinAlertRepository
{
    public async Task AddAsync(LolBinAlert alert, CancellationToken ct = default)
    {
        db.Set<LolBinAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<LolBinAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<LolBinAlert>().OrderByDescending(a => a.AlertedAtUtc).ToListAsync(ct);
}
