using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record SupplyChainAlertEventArgs(SupplyChainAlert Alert);

public interface ISupplyChainDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<SupplyChainAlertEventArgs> AlertDetected;
    Task<IReadOnlyList<SupplyChainAlert>> ScanRunningProcessesAsync(CancellationToken ct = default);
}
