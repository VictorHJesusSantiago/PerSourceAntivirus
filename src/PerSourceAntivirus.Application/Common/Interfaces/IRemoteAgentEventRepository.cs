using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IRemoteAgentEventRepository
{
    Task AddAsync(RemoteAgentEvent evt, CancellationToken ct = default);
    Task<IReadOnlyList<RemoteAgentEvent>> GetAllAsync(CancellationToken ct = default);
}
