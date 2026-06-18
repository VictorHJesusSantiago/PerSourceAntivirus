namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessMemoryScanner
{
    Task<ProcessMemoryScanResult> ScanProcessAsync(int processId, CancellationToken ct = default);
}

public record ProcessMemoryScanResult(
    int ProcessId,
    string ProcessName,
    int RegionsScanned,
    IReadOnlyList<ProcessMemoryMatch> Matches,
    bool Success,
    string? ErrorMessage = null
);

public record ProcessMemoryMatch(
    long BaseAddress,
    long RegionSize,
    string RuleIdentifier,
    IReadOnlyList<string> Tags
);
