namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMetricsExporter
{
    Task StartAsync(int port, CancellationToken ct = default);
    void Stop();
    Task<string> BuildPrometheusTextAsync(CancellationToken ct = default);
}
