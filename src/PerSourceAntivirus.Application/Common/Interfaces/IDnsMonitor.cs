namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDnsMonitor
{
    IAsyncEnumerable<DnsQueryData> WatchAsync(string? deviceName = null, CancellationToken cancellationToken = default);
}

public record DnsQueryData(
    string QueryName,
    string QueryType,
    string SourceAddress,
    bool IsSuspicious,
    string? SuspicionReason);
