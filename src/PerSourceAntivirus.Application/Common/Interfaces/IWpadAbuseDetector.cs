using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWpadAbuseDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<WpadAbuseAlertEventArgs> AlertDetected;
}

public record WpadAbuseAlertEventArgs(WpadAbuseAlert Alert);
