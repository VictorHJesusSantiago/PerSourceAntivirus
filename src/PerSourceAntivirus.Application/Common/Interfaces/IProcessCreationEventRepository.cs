using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessCreationEventRepository
{
    Task AddAsync(ProcessCreationEvent evt, CancellationToken ct = default);
    Task<IReadOnlyList<ProcessCreationEvent>> GetByProcessIdAsync(int pid, CancellationToken ct = default);
    Task<IReadOnlyList<ProcessCreationEvent>> GetRecentAsync(int count, CancellationToken ct = default);
}
