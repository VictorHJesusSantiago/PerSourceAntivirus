using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Privacy;

public sealed class MicrophoneAccessRepository(AppDbContext db) : IMicrophoneAccessRepository
{
    public async Task AddAsync(MicrophoneAccessEvent accessEvent, CancellationToken ct = default)
    {
        db.Set<MicrophoneAccessEvent>().Add(accessEvent);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<MicrophoneAccessEvent>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<MicrophoneAccessEvent>().OrderByDescending(e => e.DetectedAtUtc).ToListAsync(ct);
}
