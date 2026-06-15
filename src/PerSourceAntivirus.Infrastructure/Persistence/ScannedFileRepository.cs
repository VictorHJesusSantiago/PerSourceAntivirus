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

    public async Task<IReadOnlyList<ScannedFile>> GetAllAsync(CancellationToken cancellationToken = default)
        => await dbContext.ScannedFiles.AsNoTracking().ToListAsync(cancellationToken);
}
