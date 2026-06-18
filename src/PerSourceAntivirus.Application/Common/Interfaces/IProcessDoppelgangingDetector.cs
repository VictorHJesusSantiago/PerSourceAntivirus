using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessDoppelgangingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ProcessDoppelgangingAlertEventArgs> AlertDetected;
}

public record ProcessDoppelgangingAlertEventArgs(ProcessDoppelgangingAlert Alert);
