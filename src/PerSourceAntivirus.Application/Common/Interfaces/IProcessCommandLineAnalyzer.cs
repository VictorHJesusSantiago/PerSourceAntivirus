using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record ProcessCommandLineAlertEventArgs(ProcessCommandLineAlert Alert);

public interface IProcessCommandLineAnalyzer
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ProcessCommandLineAlertEventArgs> AlertDetected;
}
