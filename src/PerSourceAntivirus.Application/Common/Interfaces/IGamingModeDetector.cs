namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IGamingModeDetector
{
    bool IsGamingModeActive { get; }
    event EventHandler<bool> GamingModeChanged;
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
}
