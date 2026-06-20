using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IStixIocRepository
{
    Task AddRangeAsync(IEnumerable<StixIoc> iocs, CancellationToken ct = default);
    Task<IReadOnlyList<StixIoc>> GetByFeedAsync(Guid feedId, CancellationToken ct = default);
    Task<IReadOnlyList<StixIoc>> GetAllAsync(CancellationToken ct = default);
}
