using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Process;

public sealed class KeyloggerAlertRepository(AppDbContext db) : IKeyloggerAlertRepository
{
    public async Task AddAsync(KeyloggerDetectionAlert alert, CancellationToken ct = default)
    {
        db.Set<KeyloggerDetectionAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<KeyloggerDetectionAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<KeyloggerDetectionAlert>().ToListAsync(ct);
}
