using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICertificateTrustListService
{
    Task<CertificateTrustEntry?> FindByThumbprintAsync(string thumbprint, CancellationToken ct = default);
    Task AddOrUpdateAsync(string thumbprint, string subjectName, string trustLevel, string? note, CancellationToken ct = default);
    Task<IReadOnlyList<CertificateTrustEntry>> GetAllAsync(CancellationToken ct = default);
}
