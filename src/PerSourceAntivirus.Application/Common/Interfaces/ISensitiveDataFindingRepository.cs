using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISensitiveDataFindingRepository
{
    Task AddRangeAsync(IEnumerable<SensitiveDataFinding> findings, CancellationToken ct = default);
    Task<IReadOnlyList<SensitiveDataFinding>> GetAllAsync(CancellationToken ct = default);
}
