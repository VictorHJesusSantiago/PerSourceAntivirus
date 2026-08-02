using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Signatures;

public sealed class CustomSignatureMatchRepository(AppDbContext db) : ICustomSignatureMatchRepository
{
    public async Task AddAsync(CustomSignatureMatch match, CancellationToken ct = default)
    {
        db.Set<CustomSignatureMatch>().Add(match);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<CustomSignatureMatch>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<CustomSignatureMatch>().ToListAsync(ct);
}
