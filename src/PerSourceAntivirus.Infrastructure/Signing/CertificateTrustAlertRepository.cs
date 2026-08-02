using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Signing;

public sealed class CertificateTrustAlertRepository(AppDbContext db) : ICertificateTrustAlertRepository
{
    public async Task AddAsync(CertificateTrustAlert alert, CancellationToken ct = default)
    {
        db.Set<CertificateTrustAlert>().Add(alert);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<CertificateTrustAlert>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<CertificateTrustAlert>().ToListAsync(ct);
}
