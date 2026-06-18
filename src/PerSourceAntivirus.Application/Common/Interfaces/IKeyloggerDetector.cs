using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IKeyloggerDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<KeyloggerDetectionAlertEventArgs> AlertDetected;
}

public record KeyloggerDetectionAlertEventArgs(KeyloggerDetectionAlert Alert);
