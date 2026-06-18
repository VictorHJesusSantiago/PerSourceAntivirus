using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IEnhancedBeaconingDetector
{
    Task StartMonitoringAsync(string? deviceName, CancellationToken ct);
    void StopMonitoring();
    event EventHandler<BeaconingAlertEventArgs> AlertDetected;
}

public record BeaconingAlertEventArgs(BeaconingAnalysis Analysis);
