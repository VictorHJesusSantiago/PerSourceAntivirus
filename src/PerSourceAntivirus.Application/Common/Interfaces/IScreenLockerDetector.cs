using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScreenLockerDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ScreenLockerAlertEventArgs> AlertDetected;
}

public record ScreenLockerAlertEventArgs(ScreenLockerAlert Alert);
