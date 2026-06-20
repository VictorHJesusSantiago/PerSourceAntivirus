using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INetworkBehaviorAlertRepository
{
    Task AddAsync(NetworkBehaviorAlert alert, CancellationToken ct);
    Task<IReadOnlyList<NetworkBehaviorAlert>> GetAllAsync(CancellationToken ct);
}
