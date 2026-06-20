using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IStixFeedSourceRepository
{
    Task AddAsync(StixFeedSource source, CancellationToken ct = default);
    Task UpdateAsync(StixFeedSource source, CancellationToken ct = default);
    Task<IReadOnlyList<StixFeedSource>> GetAllAsync(CancellationToken ct = default);
}
