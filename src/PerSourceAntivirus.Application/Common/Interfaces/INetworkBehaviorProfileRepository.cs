using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INetworkBehaviorProfileRepository
{
    Task AddOrUpdateAsync(NetworkBehaviorProfile profile, CancellationToken ct);
    Task<NetworkBehaviorProfile?> GetByProcessNameAsync(string processName, CancellationToken ct);
    Task<IReadOnlyList<NetworkBehaviorProfile>> GetAllAsync(CancellationToken ct);
}
