using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IBrowserCredentialMonitor
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<BrowserCredentialAccessAlertEventArgs> AlertDetected;
}

public record BrowserCredentialAccessAlertEventArgs(BrowserCredentialAccessAlert Alert);
