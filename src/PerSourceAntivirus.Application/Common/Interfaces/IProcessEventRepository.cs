using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessEventRepository
{
    Task AddRangeAsync(IEnumerable<ProcessEvent> events, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ProcessEvent>> GetAllAsync(bool onlySuspicious = false, CancellationToken cancellationToken = default);
}
