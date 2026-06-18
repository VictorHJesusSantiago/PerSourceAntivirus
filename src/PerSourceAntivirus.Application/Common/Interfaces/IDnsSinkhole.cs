namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDnsSinkhole
{
    Task StartAsync(string? deviceName, CancellationToken ct);
    void Stop();
    event EventHandler<DnsSinkholeEventArgs> RequestSinkholed;
}

public record DnsSinkholeEventArgs(string QueryName, string SourceIp, int SourcePort, string SpoofedResponseIp);
