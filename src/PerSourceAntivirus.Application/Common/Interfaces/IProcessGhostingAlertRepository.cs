using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessGhostingAlertRepository
{
    Task AddAsync(ProcessGhostingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ProcessGhostingAlert>> GetAllAsync(CancellationToken ct = default);
}
