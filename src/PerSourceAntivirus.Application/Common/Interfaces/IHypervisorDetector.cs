using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHypervisorDetector
{
    Task<HypervisorDetectionResult> DetectAsync(CancellationToken ct = default);
}
