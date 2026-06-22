using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class BeaconingAnalysisRepository(AppDbContext db) : IBeaconingAnalysisRepository
{
    public async Task AddAsync(BeaconingAnalysis analysis, CancellationToken ct = default)
    {
        db.Set<BeaconingAnalysis>().Add(analysis);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<BeaconingAnalysis>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<BeaconingAnalysis>().OrderByDescending(x => x.DetectedAtUtc).ToListAsync(ct);
}
