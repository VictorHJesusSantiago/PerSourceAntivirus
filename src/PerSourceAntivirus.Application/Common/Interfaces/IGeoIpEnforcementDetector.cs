using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IGeoIpEnforcementDetector
{
    Task StartMonitoringAsync(string? deviceName, CancellationToken ct);
    void StopMonitoring();
    event EventHandler<GeoIpBlockAlertEventArgs> AlertDetected;
}

public record GeoIpBlockAlertEventArgs(GeoIpBlockAlert Alert);
