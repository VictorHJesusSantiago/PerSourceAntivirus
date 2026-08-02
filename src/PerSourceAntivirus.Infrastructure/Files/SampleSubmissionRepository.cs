using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Files;

public sealed class SampleSubmissionRepository(AppDbContext db) : ISampleSubmissionRepository
{
    public async Task AddAsync(SampleSubmissionRecord record, CancellationToken ct = default)
    {
        db.Set<SampleSubmissionRecord>().Add(record);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<SampleSubmissionRecord>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<SampleSubmissionRecord>().ToListAsync(ct);
}
