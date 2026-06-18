using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScreenLockerAlertRepository
{
    Task AddAsync(ScreenLockerAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ScreenLockerAlert>> GetAllAsync(CancellationToken ct = default);
}
