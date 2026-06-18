using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessDoppelgangingAlertRepository
{
    Task AddAsync(ProcessDoppelgangingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ProcessDoppelgangingAlert>> GetAllAsync(CancellationToken ct = default);
}
