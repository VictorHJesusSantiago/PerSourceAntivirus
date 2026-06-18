using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IStackPivotDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<StackPivotAlertEventArgs> AlertDetected;
}

public record StackPivotAlertEventArgs(StackPivotAlert Alert);
