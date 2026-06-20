namespace PerSourceAntivirus.Application.Common.Interfaces;

public record AppLockerStatus(bool IsEnabled, string PolicyMode, string[] EnforcedPaths, bool IsWdacEnabled);

public interface IAppLockerIntegration
{
    Task<AppLockerStatus> GetStatusAsync(CancellationToken ct = default);
    bool IntegrateWithAppWhitelist(IReadOnlyList<Domain.Entities.AppWhitelistEntry> entries);
}
