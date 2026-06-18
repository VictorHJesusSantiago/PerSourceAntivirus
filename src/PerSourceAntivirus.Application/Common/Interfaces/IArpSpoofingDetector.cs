using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IArpSpoofingDetector
{
    Task StartMonitoringAsync(string? deviceName, CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ArpSpoofingAlertEventArgs> AlertDetected;
}

public record ArpSpoofingAlertEventArgs(ArpSpoofingAlert Alert);
