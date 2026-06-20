namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAppContainerSandboxRunner
{
    Task<SandboxExecutionResult> RunInAppContainerAsync(string executablePath, string arguments, int timeoutSeconds, CancellationToken ct);
}

public record SandboxExecutionResult(bool Success, int ExitCode, string StandardOutput, string StandardError, bool TimedOut);
