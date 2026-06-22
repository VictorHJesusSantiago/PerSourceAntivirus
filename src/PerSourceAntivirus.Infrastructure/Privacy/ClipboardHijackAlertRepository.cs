using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Privacy;

public sealed class ClipboardHijackAlertRepository(AppDbContext db) : IClipboardHijackAlertRepository
{
    public async Task AddAsync(ClipboardHijackAlert alert, CancellationToken ct = default)
    {
        db.Set<ClipboardHijackAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<ClipboardHijackAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<ClipboardHijackAlert>().OrderByDescending(a => a.DetectedAtUtc).ToListAsync(ct);
}
