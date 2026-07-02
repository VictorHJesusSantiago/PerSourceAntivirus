using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IActiveLearningSampleRepository
{
    Task AddAsync(ActiveLearningSample sample, CancellationToken ct = default);
    Task<IReadOnlyList<ActiveLearningSample>> GetAllAsync(CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);
}
