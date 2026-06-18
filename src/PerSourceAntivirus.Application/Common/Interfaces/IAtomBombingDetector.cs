using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAtomBombingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<AtomBombingAlertEventArgs> AlertDetected;
}

public record AtomBombingAlertEventArgs(AtomBombingAlert Alert);
