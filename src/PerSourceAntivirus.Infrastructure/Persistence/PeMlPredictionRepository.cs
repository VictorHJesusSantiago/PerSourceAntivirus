using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class PeMlPredictionRepository(AppDbContext db) : IPeMlPredictionRepository
{
    public async Task AddAsync(PeMlPrediction prediction, CancellationToken ct = default)
    {
        db.PeMlPredictions.Add(prediction);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<PeMlPrediction>> GetAllAsync(
        string? classificationFilter = null, CancellationToken ct = default)
    {
        var query = db.PeMlPredictions.AsQueryable();
        if (!string.IsNullOrEmpty(classificationFilter))
            query = query.Where(p => p.Classification == classificationFilter);
        return await query.OrderByDescending(p => p.PredictedAtUtc).ToListAsync(ct);
    }
}
