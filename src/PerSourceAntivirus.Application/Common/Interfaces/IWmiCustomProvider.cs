namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWmiCustomProvider
{
    Task StartAsync(CancellationToken ct);
    void Stop();
    void PublishThreatAlert(string alertType, string processName, int severity, string details);
}
