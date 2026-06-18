using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScreenCaptureAlertRepository
{
    Task AddAsync(ScreenCaptureAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ScreenCaptureAlert>> GetAllAsync(CancellationToken ct = default);
}
