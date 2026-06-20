using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IRegistryActivityEventRepository
{
    Task AddAsync(RegistryActivityEvent evt, CancellationToken ct = default);
    Task<IReadOnlyList<RegistryActivityEvent>> GetByProcessIdAsync(int pid, CancellationToken ct = default);
    Task<IReadOnlyList<RegistryActivityEvent>> GetByKeyPathAsync(string keyPath, CancellationToken ct = default);
    Task<IReadOnlyList<RegistryActivityEvent>> GetRecentAsync(int count, CancellationToken ct = default);
}
