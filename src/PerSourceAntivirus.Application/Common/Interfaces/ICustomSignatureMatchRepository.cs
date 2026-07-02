using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICustomSignatureMatchRepository
{
    Task AddAsync(CustomSignatureMatch match, CancellationToken ct = default);
    Task<IReadOnlyList<CustomSignatureMatch>> GetAllAsync(CancellationToken ct = default);
}
