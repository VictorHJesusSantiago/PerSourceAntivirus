using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISmbLateralMovementAlertRepository
{
    Task AddAsync(SmbLateralMovementAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<SmbLateralMovementAlert>> GetAllAsync(CancellationToken ct = default);
}
