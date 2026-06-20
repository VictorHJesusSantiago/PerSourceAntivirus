using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAmsiBypassDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<AmsiBypassAlertEventArgs> AlertDetected;
}

public record AmsiBypassAlertEventArgs(AmsiBypassAlert Alert);
