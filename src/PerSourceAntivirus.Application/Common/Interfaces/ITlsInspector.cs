using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record TlsProxyStatus(bool IsRunning, int Port, string CaCertThumbprint);

public interface ITlsInspector
{
    Task StartAsync(int port = 8080, CancellationToken ct = default);
    Task StopAsync();
    TlsProxyStatus GetStatus();
    IAsyncEnumerable<TlsInspectionEvent> WatchAsync(CancellationToken ct = default);
}

public interface ITlsInspectionEventRepository
{
    Task AddAsync(TlsInspectionEvent evt, CancellationToken ct = default);
    Task<IReadOnlyList<TlsInspectionEvent>> GetRecentAsync(int count = 100, CancellationToken ct = default);
}
