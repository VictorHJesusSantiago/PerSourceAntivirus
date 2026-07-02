namespace PerSourceAntivirus.Application.Common.Interfaces;

// Outbound application firewall (Little-Snitch style): blocks all outbound network
// connections initiated by a specific executable, via the Windows Filtering Platform
// FWPM_CONDITION_ALE_APP_ID condition (per-process, not per-IP like IWfpBlocker).
public interface IProcessFirewallService
{
    Task<bool> BlockProcessAsync(string exePath, string? reason = null, CancellationToken ct = default);
    Task<bool> UnblockProcessAsync(string exePath, CancellationToken ct = default);
    Task<IReadOnlyList<string>> GetBlockedProcessesAsync(CancellationToken ct = default);

    // Re-applies every persisted "Block" rule from IProcessFirewallRuleRepository — call once at startup.
    Task RestoreRulesFromRepositoryAsync(CancellationToken ct = default);
}
