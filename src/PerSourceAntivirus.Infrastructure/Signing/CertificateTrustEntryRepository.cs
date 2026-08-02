using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Signing;

public sealed class CertificateTrustEntryRepository(AppDbContext db) : ICertificateTrustEntryRepository
{
    public async Task<CertificateTrustEntry?> FindByThumbprintAsync(string thumbprint, CancellationToken ct = default)
        => await db.Set<CertificateTrustEntry>()
            .FirstOrDefaultAsync(e => e.Thumbprint == thumbprint, ct);

    public async Task AddOrUpdateAsync(CertificateTrustEntry entry, CancellationToken ct = default)
    {
        var existing = await db.Set<CertificateTrustEntry>()
            .FirstOrDefaultAsync(e => e.Thumbprint == entry.Thumbprint, ct);

        if (existing is null)
        {
            db.Set<CertificateTrustEntry>().Add(entry);
        }
        else
        {
            existing.TrustLevel = entry.TrustLevel;
            existing.SubjectName = entry.SubjectName;
            existing.Note = entry.Note;
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<CertificateTrustEntry>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<CertificateTrustEntry>().ToListAsync(ct);
}
