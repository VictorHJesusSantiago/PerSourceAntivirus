using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INetworkIdsAlertRepository
{
    Task AddAsync(NetworkIntrusionAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<NetworkIntrusionAlert>> GetAllAsync(CancellationToken ct = default);
}
