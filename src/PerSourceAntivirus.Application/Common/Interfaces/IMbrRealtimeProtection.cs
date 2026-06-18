using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMbrRealtimeProtection
{
    Task StartAsync(CancellationToken ct);
    void Stop();
    bool IsActive { get; }
    event EventHandler<MbrWriteAttemptEventArgs> WriteAttemptDetected;
}

public record MbrWriteAttemptEventArgs(MbrWriteAttemptAlert Alert);
