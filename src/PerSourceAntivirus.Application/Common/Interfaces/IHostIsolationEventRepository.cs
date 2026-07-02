using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHostIsolationEventRepository
{
    Task AddAsync(HostIsolationEvent evt, CancellationToken ct = default);
    Task<IReadOnlyList<HostIsolationEvent>> GetAllAsync(CancellationToken ct = default);
}
