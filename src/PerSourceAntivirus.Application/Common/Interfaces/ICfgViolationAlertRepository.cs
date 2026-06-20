using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICfgViolationAlertRepository
{
    Task AddAsync(CfgViolationAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<CfgViolationAlert>> GetAllAsync(CancellationToken ct = default);
}
