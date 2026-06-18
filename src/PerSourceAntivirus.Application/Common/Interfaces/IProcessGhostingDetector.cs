using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessGhostingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ProcessGhostingAlertEventArgs> AlertDetected;
}

public record ProcessGhostingAlertEventArgs(ProcessGhostingAlert Alert);
