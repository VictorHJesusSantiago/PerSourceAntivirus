using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPuaDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<PuaAlertEventArgs> AlertDetected;
}

public record PuaAlertEventArgs(PuaAlert Alert);
