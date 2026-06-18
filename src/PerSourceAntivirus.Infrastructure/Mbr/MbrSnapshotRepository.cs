using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Mbr;

public sealed class MbrSnapshotRepository(AppDbContext db) : IMbrSnapshotRepository
{
    public async Task<MbrSnapshot?> GetLatestBaselineAsync(
        int driveIndex, CancellationToken cancellationToken = default)
        => await db.MbrSnapshots
            .Where(s => s.DriveIndex == driveIndex && s.IsBaseline)
            .OrderByDescending(s => s.TakenAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

    public async Task AddAsync(MbrSnapshot snapshot, CancellationToken cancellationToken = default)
    {
        db.MbrSnapshots.Add(snapshot);
        await db.SaveChangesAsync(cancellationToken);
    }
}
