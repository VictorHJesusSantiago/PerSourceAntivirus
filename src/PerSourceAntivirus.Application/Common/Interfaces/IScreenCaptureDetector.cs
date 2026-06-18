using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScreenCaptureDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ScreenCaptureAlertEventArgs> AlertDetected;
}

public record ScreenCaptureAlertEventArgs(ScreenCaptureAlert Alert);
