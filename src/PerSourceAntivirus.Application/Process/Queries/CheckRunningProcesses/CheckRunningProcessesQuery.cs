using MediatR;

namespace PerSourceAntivirus.Application.Process.Queries.CheckRunningProcesses;

public record CheckRunningProcessesQuery : IRequest<IReadOnlyList<RunningProcessResult>>;

public record RunningProcessResult(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath,
    string? Sha256Hash,
    bool IsMalicious,
    string? ReputationSource,
    string? ReportUrl);
