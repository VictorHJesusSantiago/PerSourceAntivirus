using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Forensics;

public sealed class HypervisorDetectionResultRepository(AppDbContext db) : IHypervisorDetectionResultRepository
{
    public async Task AddAsync(HypervisorDetectionResult result, CancellationToken ct)
    {
        db.Set<HypervisorDetectionResult>().Add(result);
        await db.SaveChangesAsync(ct);
    }

    public async Task<HypervisorDetectionResult?> GetLatestAsync(CancellationToken ct)
        => await db.Set<HypervisorDetectionResult>()
            .OrderByDescending(r => r.DetectedAtUtc)
            .FirstOrDefaultAsync(ct);
}
