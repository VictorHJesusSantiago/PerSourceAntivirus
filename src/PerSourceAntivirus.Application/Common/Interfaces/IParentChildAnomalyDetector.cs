using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record ParentChildAnomalyAlertEventArgs(ParentChildAnomalyAlert Alert);

public interface IParentChildAnomalyDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ParentChildAnomalyAlertEventArgs> AlertDetected;
}
