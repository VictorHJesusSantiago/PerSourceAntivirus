using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Privacy;

public sealed class WebcamAccessRepository(AppDbContext db) : IWebcamAccessRepository
{
    public async Task AddAsync(WebcamAccessEvent accessEvent, CancellationToken ct = default)
    {
        db.Set<WebcamAccessEvent>().Add(accessEvent);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<WebcamAccessEvent>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<WebcamAccessEvent>().OrderByDescending(e => e.DetectedAtUtc).ToListAsync(ct);
}
