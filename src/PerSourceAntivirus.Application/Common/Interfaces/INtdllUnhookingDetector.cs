using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INtdllUnhookingDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<NtdllUnhookingAlertEventArgs> AlertDetected;
}

public record NtdllUnhookingAlertEventArgs(NtdllUnhookingAlert Alert);
