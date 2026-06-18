using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ILlmnrPoisoningDetector
{
    Task StartMonitoringAsync(string? deviceName, CancellationToken ct);
    void StopMonitoring();
    event EventHandler<LlmnrPoisoningAlertEventArgs> AlertDetected;
}

public record LlmnrPoisoningAlertEventArgs(LlmnrPoisoningAlert Alert);
