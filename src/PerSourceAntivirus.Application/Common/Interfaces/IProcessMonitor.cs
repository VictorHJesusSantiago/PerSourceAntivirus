namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessMonitor
{
    IAsyncEnumerable<ProcessEventData> WatchAsync(CancellationToken cancellationToken = default);
}

public record ProcessEventData(
    int ProcessId,
    string ProcessName,
    int ParentProcessId,
    string ParentProcessName,
    string CommandLine,
    bool IsSuspicious,
    string? SuspicionReason);
