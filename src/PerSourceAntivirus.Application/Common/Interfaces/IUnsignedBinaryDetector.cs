using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IUnsignedBinaryDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<UnsignedBinaryAlertEventArgs> AlertDetected;
}

public record UnsignedBinaryAlertEventArgs(UnsignedBinaryAlert Alert);
