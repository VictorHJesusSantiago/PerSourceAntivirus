using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPlaybookExecutionLogRepository
{
    Task AddAsync(PlaybookExecutionLog log, CancellationToken ct = default);
    Task<IReadOnlyList<PlaybookExecutionLog>> GetAllAsync(CancellationToken ct = default);
}
