using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDnsTunnelingDetector
{
    Task StartMonitoringAsync(string? deviceName, CancellationToken ct);
    void StopMonitoring();
    event EventHandler<DnsTunnelingAlertEventArgs> AlertDetected;
}

public record DnsTunnelingAlertEventArgs(DnsTunnelingAlert Alert);
