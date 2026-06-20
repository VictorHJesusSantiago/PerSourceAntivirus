using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBrowserExtensionFindingRepository
{
    Task AddRangeAsync(IEnumerable<BrowserExtensionFinding> findings, CancellationToken ct = default);
    Task<IReadOnlyList<BrowserExtensionFinding>> GetAllAsync(CancellationToken ct = default);
}
