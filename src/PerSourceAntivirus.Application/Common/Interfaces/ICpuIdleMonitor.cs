namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICpuIdleMonitor
{
    bool IsCpuBusy { get; }
    bool IsOnBattery { get; }
    event EventHandler<bool> CpuBusyChanged;
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
}
