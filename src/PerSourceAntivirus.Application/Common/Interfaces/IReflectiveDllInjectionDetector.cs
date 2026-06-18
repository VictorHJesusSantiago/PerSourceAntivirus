using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IReflectiveDllInjectionDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ReflectiveDllInjectionAlertEventArgs> AlertDetected;
}

public record ReflectiveDllInjectionAlertEventArgs(ReflectiveDllInjectionAlert Alert);
