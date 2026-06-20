using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICustomIocRepository
{
    Task AddAsync(CustomIoc ioc, CancellationToken ct = default);
    Task<IReadOnlyList<CustomIoc>> GetAllAsync(CancellationToken ct = default);
    Task RemoveAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<CustomIoc>> GetByTypeAsync(string type, CancellationToken ct = default);
}
