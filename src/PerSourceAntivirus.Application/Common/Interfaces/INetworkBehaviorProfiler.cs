using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record NetworkBehaviorAlertEventArgs(NetworkBehaviorAlert Alert);

public interface INetworkBehaviorProfiler
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<NetworkBehaviorAlertEventArgs> AlertDetected;
    Task<NetworkBehaviorProfile?> GetProfileAsync(string processName, CancellationToken ct = default);
}
