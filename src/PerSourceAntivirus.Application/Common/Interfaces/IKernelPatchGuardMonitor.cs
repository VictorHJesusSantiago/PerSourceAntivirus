using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record KernelPatchGuardAlertEventArgs(KernelPatchGuardAlert Alert);

public interface IKernelPatchGuardMonitor
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<KernelPatchGuardAlertEventArgs> AlertDetected;
}
