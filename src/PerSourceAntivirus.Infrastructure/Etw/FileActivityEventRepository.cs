using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Etw;

public sealed class FileActivityEventRepository(AppDbContext db) : IFileActivityEventRepository
{
    public async Task AddAsync(FileActivityEvent evt, CancellationToken ct = default)
    {
        db.Set<FileActivityEvent>().Add(evt);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<FileActivityEvent>> GetByProcessIdAsync(int pid, CancellationToken ct = default)
        => await db.Set<FileActivityEvent>()
            .Where(e => e.ProcessId == pid)
            .OrderByDescending(e => e.OccurredAtUtc)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<FileActivityEvent>> GetByFilePathAsync(string path, CancellationToken ct = default)
        => await db.Set<FileActivityEvent>()
            .Where(e => e.FilePath.Contains(path))
            .OrderByDescending(e => e.OccurredAtUtc)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<FileActivityEvent>> GetRecentAsync(int count = 1000, CancellationToken ct = default)
        => await db.Set<FileActivityEvent>()
            .OrderByDescending(e => e.OccurredAtUtc)
            .Take(count)
            .ToListAsync(ct);
}
