using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IRansomwareMonitor
{
    IAsyncEnumerable<RansomwareAlert> WatchAsync(CancellationToken ct = default);
}
