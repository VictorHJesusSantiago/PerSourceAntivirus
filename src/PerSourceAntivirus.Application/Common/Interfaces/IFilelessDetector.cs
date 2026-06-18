using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IFilelessDetector
{
    Task StartMonitoringAsync(CancellationToken ct = default);
    void StopMonitoring();
    event EventHandler<FilelessAlert>? AlertDetected;
}
