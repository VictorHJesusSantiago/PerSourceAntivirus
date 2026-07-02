namespace PerSourceAntivirus.Application.Common.Interfaces;

// One-click network kill-switch: blocks all inbound/outbound IPv4/IPv6 traffic except
// loopback, for use when an infection is confirmed and lateral movement/exfiltration must be
// stopped immediately. RestoreAsync removes the block.
public interface IHostIsolationService
{
    Task IsolateAsync(string reason, CancellationToken ct = default);
    Task RestoreAsync(CancellationToken ct = default);
    bool IsIsolated { get; }
}
