using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INetworkConnectionEventRepository
{
    Task AddRangeAsync(IEnumerable<NetworkConnectionEvent> events, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<NetworkConnectionEvent>> GetAllAsync(bool onlyBlocklisted, CancellationToken cancellationToken = default);
}
