namespace PerSourceAntivirus.Application.Common.Interfaces;

public record BehaviorReport(
    string FilePath,
    bool ExecutedSuccessfully,
    TimeSpan ExecutionTime,
    IReadOnlyList<string> ProcessesCreated,
    IReadOnlyList<string> FilesCreated,
    IReadOnlyList<string> FilesDeleted,
    IReadOnlyList<string> RegistryKeysModified,
    IReadOnlyList<string> NetworkConnections,
    IReadOnlyList<string> SuspiciousIndicators,
    string OverallVerdict,
    string? ErrorMessage = null
);

public interface IEnhancedSandboxRunner
{
    Task<BehaviorReport> AnalyzeAsync(string filePath, TimeSpan timeout, CancellationToken ct = default);
}
