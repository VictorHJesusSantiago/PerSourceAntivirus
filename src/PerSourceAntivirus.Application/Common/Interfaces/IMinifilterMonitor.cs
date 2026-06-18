namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMinifilterMonitor
{
    IAsyncEnumerable<MinifilterEvent> WatchAsync(CancellationToken ct = default);
}

public record MinifilterEvent(
    DateTime DetectedAtUtc,
    string FilePath,
    int ProcessId,
    bool Blocked,
    string? BlockReason
);
