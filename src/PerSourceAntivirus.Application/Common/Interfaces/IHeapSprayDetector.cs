using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IHeapSprayDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<HeapSprayAlertEventArgs> AlertDetected;
}

public record HeapSprayAlertEventArgs(HeapSprayAlert Alert);
