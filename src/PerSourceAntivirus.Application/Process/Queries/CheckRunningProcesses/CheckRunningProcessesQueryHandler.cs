using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Process.Queries.CheckRunningProcesses;

public class CheckRunningProcessesQueryHandler(
    IRunningProcessProvider processProvider,
    IFileHashCalculator hashCalculator,
    IHashReputationService reputationService)
    : IRequestHandler<CheckRunningProcessesQuery, IReadOnlyList<RunningProcessResult>>
{
    public async Task<IReadOnlyList<RunningProcessResult>> Handle(
        CheckRunningProcessesQuery request, CancellationToken cancellationToken)
    {
        var snapshot = processProvider.GetSnapshot();
        var results  = new List<RunningProcessResult>(snapshot.Count);

        // Cache hash+reputation per unique exe path to avoid hashing the same binary N times
        // (e.g., dozens of svchost.exe instances sharing one path).
        var cache = new Dictionary<string, (string? Hash, bool IsMalicious, string? Source, string? Url)>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var proc in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (proc.ExecutablePath is null)
            {
                results.Add(new RunningProcessResult(
                    proc.ProcessId, proc.ProcessName, null, null, false, null, null));
                continue;
            }

            if (!cache.ContainsKey(proc.ExecutablePath))
                cache[proc.ExecutablePath] = await ComputeReputationAsync(proc.ExecutablePath, cancellationToken);

            var (hash, malicious, source, url) = cache[proc.ExecutablePath];
            results.Add(new RunningProcessResult(
                proc.ProcessId, proc.ProcessName, proc.ExecutablePath, hash, malicious, source, url));
        }

        return results;
    }

    private async Task<(string? Hash, bool IsMalicious, string? Source, string? Url)>
        ComputeReputationAsync(string exePath, CancellationToken cancellationToken)
    {
        try
        {
            var hashResult = await hashCalculator.ComputeAsync(exePath, cancellationToken);
            var rep        = await reputationService.CheckAsync(hashResult.Sha256Hash, cancellationToken);
            return rep is null
                ? (hashResult.Sha256Hash, false, null, null)
                : (hashResult.Sha256Hash, rep.IsMalicious, rep.Source, rep.ReportUrl);
        }
        catch
        {
            // File locked, access denied, or process exited between snapshot and hash read.
            return (null, false, null, null);
        }
    }
}
