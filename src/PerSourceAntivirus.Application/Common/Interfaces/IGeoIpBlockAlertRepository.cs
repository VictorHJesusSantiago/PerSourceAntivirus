using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IGeoIpBlockAlertRepository
{
    Task AddAsync(GeoIpBlockAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<GeoIpBlockAlert>> GetAllAsync(CancellationToken ct = default);
}
