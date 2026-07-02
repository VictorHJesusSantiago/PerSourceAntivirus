using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

// "Manager" mode: listens on UDP for CEF-over-syslog messages emitted by other
// PerSourceAntivirus installs' ISiemExporter (SyslogUdp), turning one PC into a lightweight
// central collector for a small local network of agents.
public interface ISyslogCefIngestionService
{
    Task StartAsync(int port, CancellationToken ct = default);
    void Stop();
    event EventHandler<RemoteAgentEventArgs> EventReceived;
}

public record RemoteAgentEventArgs(RemoteAgentEvent Event);
