using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IComHijackMonitor
{
    IAsyncEnumerable<ComHijackAlert> WatchAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ComHijackAlert>> ScanCurrentStateAsync(CancellationToken ct = default);
}

public interface IComHijackAlertRepository
{
    Task AddAsync(ComHijackAlert alert, CancellationToken ct = default);
    Task<IReadOnlyList<ComHijackAlert>> GetAllAsync(CancellationToken ct = default);
}
