using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

public sealed class ApiCallSequenceAlertRepository(AppDbContext db) : IApiCallSequenceAlertRepository
{
    public async Task AddAsync(ApiCallSequenceAlert alert, CancellationToken ct)
    {
        db.Set<ApiCallSequenceAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ApiCallSequenceAlert>> GetAllAsync(CancellationToken ct)
        => await db.Set<ApiCallSequenceAlert>()
            .OrderByDescending(a => a.DetectedAtUtc)
            .ToListAsync(ct);
}
