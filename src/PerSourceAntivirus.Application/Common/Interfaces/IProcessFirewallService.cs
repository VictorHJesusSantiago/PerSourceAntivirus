namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessFirewallService
{
    Task<bool> BlockProcessAsync(string exePath, string? reason = null, CancellationToken ct = default);
    Task<bool> UnblockProcessAsync(string exePath, CancellationToken ct = default);
    Task<IReadOnlyList<string>> GetBlockedProcessesAsync(CancellationToken ct = default);

    Task RestoreRulesFromRepositoryAsync(CancellationToken ct = default);
}
