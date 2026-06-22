using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

public sealed class HeapSprayAlertRepository(AppDbContext db) : IHeapSprayAlertRepository
{
    public async Task AddAsync(HeapSprayAlert alert, CancellationToken ct = default)
    {
        db.Set<HeapSprayAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<HeapSprayAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<HeapSprayAlert>().ToListAsync(ct);
}
