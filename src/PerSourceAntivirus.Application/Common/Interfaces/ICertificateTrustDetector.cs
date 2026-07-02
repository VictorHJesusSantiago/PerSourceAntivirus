using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICertificateTrustDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<CertificateTrustAlertEventArgs> AlertDetected;
}

public record CertificateTrustAlertEventArgs(CertificateTrustAlert Alert);
