using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IRansomwareAlertRepository
{
    Task AddAsync(RansomwareAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<RansomwareAlert>> GetAllAsync(bool onlyCritical = false, CancellationToken ct = default);
}
