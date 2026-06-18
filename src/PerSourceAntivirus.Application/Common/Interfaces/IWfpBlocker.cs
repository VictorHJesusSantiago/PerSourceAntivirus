namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWfpBlocker
{
    Task<WfpBlockResult> AddBlockAsync(string ipAddress, string reason = "", CancellationToken ct = default);
    Task<bool> RemoveBlockAsync(string ipAddress, CancellationToken ct = default);
    Task<IReadOnlyList<WfpBlockEntry>> GetActiveBlocksAsync(CancellationToken ct = default);
    Task<int> SyncFromIpListAsync(IEnumerable<string> ipAddresses, CancellationToken ct = default);
}

public record WfpBlockResult(
    bool Success,
    ulong FilterIdOutboundV4,
    ulong FilterIdInboundV4,
    string? ErrorMessage = null
);

public record WfpBlockEntry(
    string IpAddress,
    ulong FilterIdOutboundV4,
    ulong FilterIdInboundV4,
    string Reason,
    DateTime AddedAt
);
