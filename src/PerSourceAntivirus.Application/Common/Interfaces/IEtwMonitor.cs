namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IEtwMonitor
{
    IAsyncEnumerable<EtwEventData> WatchAsync(CancellationToken cancellationToken = default);
}

public record EtwEventData(
    DateTime DetectedAtUtc,
    EtwEventType EventType,
    int ProcessId,
    string ProcessName,
    string Detail,
    bool IsSuspicious,
    string? SuspicionReason);

public enum EtwEventType
{
    DllLoad,
    RegistryWrite,
    ProcessCreate,
    Other,
}
