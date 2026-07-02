using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICertificateTrustEntryRepository
{
    Task<CertificateTrustEntry?> FindByThumbprintAsync(string thumbprint, CancellationToken ct = default);
    Task AddOrUpdateAsync(CertificateTrustEntry entry, CancellationToken ct = default);
    Task<IReadOnlyList<CertificateTrustEntry>> GetAllAsync(CancellationToken ct = default);
}
