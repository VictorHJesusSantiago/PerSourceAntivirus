namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISandboxRunner
{
    Task<SandboxRunResult> RunAsync(
        string exePath,
        int timeoutSeconds = 30,
        CancellationToken cancellationToken = default);
}

public record SandboxRunResult(
    int? ExitCode,
    TimeSpan Duration,
    bool KilledByTimeout,
    bool CreatedChildProcess,
    bool MemoryLimitExceeded,
    string? ErrorMessage);
