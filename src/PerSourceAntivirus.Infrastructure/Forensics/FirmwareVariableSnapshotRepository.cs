using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Forensics;

public sealed class FirmwareVariableSnapshotRepository(AppDbContext db) : IFirmwareVariableSnapshotRepository
{
    public async Task AddRangeAsync(IEnumerable<FirmwareVariableSnapshot> snapshots, CancellationToken ct)
    {
        db.Set<FirmwareVariableSnapshot>().AddRange(snapshots);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<FirmwareVariableSnapshot>> GetAllAsync(CancellationToken ct)
        => await db.Set<FirmwareVariableSnapshot>().OrderByDescending(s => s.SnapshotAtUtc).ToListAsync(ct);

    public async Task<IReadOnlyList<FirmwareVariableSnapshot>> GetBaselineAsync(CancellationToken ct)
    {
        var all = await db.Set<FirmwareVariableSnapshot>()
            .OrderBy(s => s.VariableName)
            .ThenBy(s => s.SnapshotAtUtc)
            .ToListAsync(ct);

        return all
            .GroupBy(s => s.VariableName)
            .Select(g => g.First())
            .ToList();
    }
}
