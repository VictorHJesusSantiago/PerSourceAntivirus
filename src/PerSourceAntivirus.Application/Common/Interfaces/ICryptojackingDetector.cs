using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICryptojackingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<CryptojackingAlertEventArgs> AlertDetected;
}

public record CryptojackingAlertEventArgs(CryptojackingAlert Alert);
