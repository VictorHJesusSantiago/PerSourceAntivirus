using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IKeyloggerAlertRepository
{
    Task AddAsync(KeyloggerDetectionAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<KeyloggerDetectionAlert>> GetAllAsync(CancellationToken ct = default);
}
