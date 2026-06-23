using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

// TODO: Register in DependencyInjection.cs as: services.AddScoped<IStackPivotAlertRepository, StackPivotAlertRepository>();
public sealed class StackPivotAlertRepository(AppDbContext db) : IStackPivotAlertRepository
{
    public async Task AddAsync(StackPivotAlert alert, CancellationToken ct = default)
    {
        db.Set<StackPivotAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<StackPivotAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<StackPivotAlert>().ToListAsync(ct);
}
