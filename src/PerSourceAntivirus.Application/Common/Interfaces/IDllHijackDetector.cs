using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDllHijackDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<DllHijackAlertEventArgs> AlertDetected;
}

public record DllHijackAlertEventArgs(DllHijackAlert Alert);
