using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Common.Interfaces;
public interface IRootkitFindingRepository
{
    Task AddRangeAsync(IEnumerable<RootkitFinding> findings, CancellationToken ct = default);
    Task<IReadOnlyList<RootkitFinding>> GetAllAsync(CancellationToken ct = default);
}
