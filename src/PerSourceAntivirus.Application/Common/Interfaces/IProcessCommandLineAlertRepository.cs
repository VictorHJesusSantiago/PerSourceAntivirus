using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessCommandLineAlertRepository
{
    Task AddAsync(ProcessCommandLineAlert alert, CancellationToken ct);
    Task<IReadOnlyList<ProcessCommandLineAlert>> GetAllAsync(CancellationToken ct);
}
