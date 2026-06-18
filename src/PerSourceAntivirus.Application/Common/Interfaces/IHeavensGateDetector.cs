using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHeavensGateDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<HeavensGateAlertEventArgs> AlertDetected;
}

public record HeavensGateAlertEventArgs(HeavensGateAlert Alert);
