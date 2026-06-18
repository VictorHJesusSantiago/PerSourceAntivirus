using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IClipboardHijackDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ClipboardHijackAlertEventArgs> AlertDetected;
}

public record ClipboardHijackAlertEventArgs(ClipboardHijackAlert Alert);
