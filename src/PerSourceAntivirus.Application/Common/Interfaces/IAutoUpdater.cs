namespace PerSourceAntivirus.Application.Common.Interfaces;

public record UpdateCheckResult(bool UpdateAvailable, string CurrentVersion, string LatestVersion, string[] UpdatedComponents);

public interface IAutoUpdater
{
    Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken ct = default);
    Task<int> ApplyUpdatesAsync(CancellationToken ct = default);
}
