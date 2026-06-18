using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMicrophoneAccessMonitor
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<MicrophoneAccessEventArgs> AlertDetected;
}

public record MicrophoneAccessEventArgs(MicrophoneAccessEvent Event);
