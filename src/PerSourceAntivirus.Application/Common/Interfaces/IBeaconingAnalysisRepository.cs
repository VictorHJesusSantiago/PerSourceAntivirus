using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBeaconingAnalysisRepository
{
    Task AddAsync(BeaconingAnalysis analysis, CancellationToken ct = default);
    Task<IReadOnlyList<BeaconingAnalysis>> GetAllAsync(CancellationToken ct = default);
}
