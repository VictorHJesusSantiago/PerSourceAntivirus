using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPeMlPredictionRepository
{
    Task AddAsync(PeMlPrediction prediction, CancellationToken ct = default);
    Task<IReadOnlyList<PeMlPrediction>> GetAllAsync(string? classificationFilter = null, CancellationToken ct = default);
}
