using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

public sealed class NtdllUnhookingAlertRepository(AppDbContext db) : INtdllUnhookingAlertRepository
{
    public async Task AddAsync(NtdllUnhookingAlert alert, CancellationToken ct = default)
    {
        db.Set<NtdllUnhookingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<NtdllUnhookingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<NtdllUnhookingAlert>().ToListAsync(ct);
}
