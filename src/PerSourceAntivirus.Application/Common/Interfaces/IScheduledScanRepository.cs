using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScheduledScanRepository
{
    Task AddAsync(ScheduledScan scan, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ScheduledScan>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ScheduledScan>> GetDueScansAsync(CancellationToken cancellationToken = default);
    Task UpdateLastRunAsync(Guid id, DateTime lastRunAtUtc, CancellationToken cancellationToken = default);
    Task RemoveAsync(Guid id, CancellationToken cancellationToken = default);
}
