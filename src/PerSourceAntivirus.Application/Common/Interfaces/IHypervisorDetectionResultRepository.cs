using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHypervisorDetectionResultRepository
{
    Task AddAsync(HypervisorDetectionResult result, CancellationToken ct);
    Task<HypervisorDetectionResult?> GetLatestAsync(CancellationToken ct);
}
