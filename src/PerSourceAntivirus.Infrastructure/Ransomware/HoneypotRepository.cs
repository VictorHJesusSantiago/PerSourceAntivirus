using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Ransomware;

public class HoneypotRepository(AppDbContext db) : IHoneypotRepository
{
    public async Task AddAsync(HoneypotFile file, CancellationToken ct = default)
    {
        db.HoneypotFiles.Add(file);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<HoneypotFile>> GetAllAsync(CancellationToken ct = default)
        => await db.HoneypotFiles.OrderBy(f => f.CreatedAtUtc).ToListAsync(ct);

    public async Task UpdateAsync(HoneypotFile file, CancellationToken ct = default)
    {
        db.HoneypotFiles.Update(file);
        await db.SaveChangesAsync(ct);
    }
}
