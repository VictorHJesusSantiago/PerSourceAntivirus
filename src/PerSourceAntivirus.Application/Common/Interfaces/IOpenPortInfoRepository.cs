using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IOpenPortInfoRepository
{
    Task AddRangeAsync(IEnumerable<OpenPortInfo> ports, CancellationToken ct = default);
    Task<IReadOnlyList<OpenPortInfo>> GetAllAsync(CancellationToken ct = default);
}
