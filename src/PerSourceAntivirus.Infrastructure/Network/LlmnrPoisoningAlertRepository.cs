using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Network;

public sealed class LlmnrPoisoningAlertRepository(AppDbContext db) : ILlmnrPoisoningAlertRepository
{
    public async Task AddAsync(LlmnrPoisoningAlert alert, CancellationToken ct = default)
    {
        db.Set<LlmnrPoisoningAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<LlmnrPoisoningAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<LlmnrPoisoningAlert>().ToListAsync(ct);
}
