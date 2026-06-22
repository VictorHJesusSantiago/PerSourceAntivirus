using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Investigation;

public sealed class AlertTriageRepository(AppDbContext db) : IAlertTriageRepository
{
    public async Task AddAsync(AlertTriage triage, CancellationToken ct = default)
    {
        db.Set<AlertTriage>().Add(triage);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(AlertTriage triage, CancellationToken ct = default)
    {
        db.Set<AlertTriage>().Update(triage);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AlertTriage>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<AlertTriage>().OrderByDescending(t => t.CreatedAtUtc).ToListAsync(ct);

    public async Task<IReadOnlyList<AlertTriage>> GetByStatusAsync(string status, CancellationToken ct = default)
        => await db.Set<AlertTriage>()
            .Where(t => t.Status == status)
            .OrderByDescending(t => t.CreatedAtUtc)
            .ToListAsync(ct);
}
