using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessHollowingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ProcessHollowingAlertEventArgs> AlertDetected;
}

public record ProcessHollowingAlertEventArgs(ProcessHollowingAlert Alert);
