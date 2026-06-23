using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<ITransactedHollowingAlertRepository, TransactedHollowingAlertRepository>();
public sealed class TransactedHollowingAlertRepository(AppDbContext db) : ITransactedHollowingAlertRepository
{
    public async Task AddAsync(TransactedHollowingAlert alert, CancellationToken ct = default)
    {
        db.Set<TransactedHollowingAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<TransactedHollowingAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<TransactedHollowingAlert>().ToListAsync(ct);
}
