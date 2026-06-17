using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class ScannedFileRepository(AppDbContext dbContext) : IScannedFileRepository
{
    public async Task AddAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default)
    {
        dbContext.ScannedFiles.Add(scannedFile);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<ScannedFile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        => await dbContext.ScannedFiles
            .Include(f => f.YaraMatches)
            .Include(f => f.PeAnalysis)
            .Include(f => f.ScriptAnalysis)
            .Include(f => f.HashReputation)
            .FirstOrDefaultAsync(f => f.Id == id, cancellationToken);

    public async Task<IReadOnlyList<ScannedFile>> GetAllAsync(CancellationToken cancellationToken = default)
        => await dbContext.ScannedFiles
            .AsNoTracking()
            .Include(f => f.YaraMatches)
            .Include(f => f.PeAnalysis)
            .Include(f => f.ScriptAnalysis)
            .Include(f => f.HashReputation)
            .ToListAsync(cancellationToken);

    public async Task UpdateAsync(ScannedFile scannedFile, CancellationToken cancellationToken = default)
    {
        dbContext.ScannedFiles.Update(scannedFile);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyDictionary<string, string>> GetExistingHashesAsync(
        IEnumerable<string> filePaths,
        CancellationToken cancellationToken = default)
    {
        var pathList = filePaths.ToList();
        var rows = await dbContext.ScannedFiles
            .AsNoTracking()
            .Where(f => pathList.Contains(f.FilePath))
            .Select(f => new { f.FilePath, f.Sha256Hash, f.ScannedAtUtc })
            .ToListAsync(cancellationToken);

        return rows
            .GroupBy(r => r.FilePath)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(r => r.ScannedAtUtc).First().Sha256Hash);
    }
}
