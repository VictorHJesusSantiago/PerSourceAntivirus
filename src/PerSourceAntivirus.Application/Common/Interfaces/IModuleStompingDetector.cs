using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IModuleStompingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ModuleStompingAlertEventArgs> AlertDetected;
}

public record ModuleStompingAlertEventArgs(ModuleStompingAlert Alert);
