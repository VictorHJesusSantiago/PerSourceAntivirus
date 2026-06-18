namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IKernelEventMonitor
{
    IAsyncEnumerable<KernelEvent> WatchAsync(CancellationToken ct = default);
}

public record KernelEvent(
    DateTime DetectedAtUtc,
    KernelEventType EventType,
    int ProcessId,
    int ParentProcessId,
    string ImagePath,
    string? CommandLine,
    ulong ImageBase,
    uint AccessMaskStripped
);

public enum KernelEventType
{
    ProcessCreate    = 1,
    ProcessTerminate = 2,
    ImageLoad        = 3,
    HandleStripped   = 4
}
