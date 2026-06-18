using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ITransactedHollowingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<TransactedHollowingAlertEventArgs> AlertDetected;
}

public record TransactedHollowingAlertEventArgs(TransactedHollowingAlert Alert);
