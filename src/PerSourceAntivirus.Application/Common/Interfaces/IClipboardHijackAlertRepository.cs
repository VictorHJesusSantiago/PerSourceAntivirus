using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IClipboardHijackAlertRepository
{
    Task AddAsync(ClipboardHijackAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ClipboardHijackAlert>> GetAllAsync(CancellationToken ct = default);
}
