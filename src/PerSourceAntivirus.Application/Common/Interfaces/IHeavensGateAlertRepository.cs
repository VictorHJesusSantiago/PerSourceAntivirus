using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHeavensGateAlertRepository
{
    Task AddAsync(HeavensGateAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<HeavensGateAlert>> GetAllAsync(CancellationToken ct = default);
}
