using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWfpBlockRepository
{
    Task AddAsync(WfpBlock block, CancellationToken ct = default);
    Task DeactivateAsync(string ipAddress, CancellationToken ct = default);
    Task<IReadOnlyList<string>> GetActiveIpsAsync(CancellationToken ct = default);
    Task<IReadOnlyList<WfpBlock>> GetAllAsync(CancellationToken ct = default);
}
