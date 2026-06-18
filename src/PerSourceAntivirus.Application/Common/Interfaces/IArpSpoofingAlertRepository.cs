using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IArpSpoofingAlertRepository
{
    Task AddAsync(ArpSpoofingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ArpSpoofingAlert>> GetAllAsync(CancellationToken ct = default);
}
