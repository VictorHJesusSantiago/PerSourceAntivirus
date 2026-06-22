using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Privacy;

public sealed class ScreenCaptureAlertRepository(AppDbContext db) : IScreenCaptureAlertRepository
{
    public async Task AddAsync(ScreenCaptureAlert alert, CancellationToken ct = default)
    {
        db.Set<ScreenCaptureAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ScreenCaptureAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ScreenCaptureAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
