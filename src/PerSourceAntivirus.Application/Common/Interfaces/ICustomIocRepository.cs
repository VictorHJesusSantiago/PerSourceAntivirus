using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICustomIocRepository
{
    Task AddAsync(CustomIoc ioc, CancellationToken ct = default);
    Task<IReadOnlyList<CustomIoc>> GetAllAsync(CancellationToken ct = default);
    Task RemoveAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<CustomIoc>> GetByTypeAsync(string type, CancellationToken ct = default);

    // Filters server-side by exact value — avoids loading the whole active-IOC table into
    // memory just to check whether one IP/domain/hash is present (see IpDomainReputationScoringService).
    Task<IReadOnlyList<CustomIoc>> FindActiveByValueAsync(string value, CancellationToken ct = default);
}
