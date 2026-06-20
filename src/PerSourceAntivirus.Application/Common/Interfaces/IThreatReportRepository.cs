using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IThreatReportRepository
{
    Task AddAsync(ThreatReport report, CancellationToken ct);
    Task<IReadOnlyList<ThreatReport>> GetAllAsync(CancellationToken ct);
}
