using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISyslogCefIngestionService
{
    Task StartAsync(int port, CancellationToken ct = default);
    void Stop();
    event EventHandler<RemoteAgentEventArgs> EventReceived;
}

public record RemoteAgentEventArgs(RemoteAgentEvent Event);
