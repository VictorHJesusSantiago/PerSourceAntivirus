using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICertificateTrustAlertRepository
{
    Task AddAsync(CertificateTrustAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<CertificateTrustAlert>> GetAllAsync(CancellationToken ct = default);
}
