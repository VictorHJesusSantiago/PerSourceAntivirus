using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPortScanDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<PortScanAlertEventArgs> AlertDetected;
}

public record PortScanAlertEventArgs(PortScanAlert Alert);
