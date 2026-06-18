using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessHollowingAlertRepository
{
    Task AddAsync(ProcessHollowingAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ProcessHollowingAlert>> GetAllAsync(CancellationToken ct = default);
}
