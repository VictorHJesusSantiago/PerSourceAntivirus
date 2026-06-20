using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICustomIocService
{
    Task<IReadOnlyList<CustomIoc>> GetAllAsync(CancellationToken ct = default);
    Task AddAsync(CustomIoc ioc, CancellationToken ct = default);
    Task RemoveAsync(Guid id, CancellationToken ct = default);
    Task<bool> IsKnownMaliciousAsync(string value, string iocType, CancellationToken ct = default);
}
