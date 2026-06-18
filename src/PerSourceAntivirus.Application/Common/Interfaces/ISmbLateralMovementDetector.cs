using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISmbLateralMovementDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<SmbLateralMovementAlertEventArgs> AlertDetected;
}

public record SmbLateralMovementAlertEventArgs(SmbLateralMovementAlert Alert);
