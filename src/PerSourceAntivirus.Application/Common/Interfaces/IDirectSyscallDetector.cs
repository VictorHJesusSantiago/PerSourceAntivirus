using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDirectSyscallDetector
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<DirectSyscallAlertEventArgs> AlertDetected;
}

public record DirectSyscallAlertEventArgs(DirectSyscallAlert Alert);
