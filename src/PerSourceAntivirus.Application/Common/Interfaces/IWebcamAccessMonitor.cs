using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWebcamAccessMonitor
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<WebcamAccessEventArgs> AlertDetected;
}

public record WebcamAccessEventArgs(WebcamAccessEvent Event);
