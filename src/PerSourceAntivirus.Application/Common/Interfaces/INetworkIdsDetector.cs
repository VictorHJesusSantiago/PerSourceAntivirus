using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INetworkIdsDetector
{
    Task StartMonitoringAsync(string? deviceName, CancellationToken ct);
    void StopMonitoring();
    event EventHandler<NetworkIdsAlertEventArgs> AlertDetected;
}

public record NetworkIdsAlertEventArgs(NetworkIntrusionAlert Alert);
