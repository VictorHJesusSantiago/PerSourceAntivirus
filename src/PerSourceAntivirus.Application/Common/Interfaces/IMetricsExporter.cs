namespace PerSourceAntivirus.Application.Common.Interfaces;

// Exposes internal alert/scan counters as a Prometheus text-exposition endpoint
// (http://127.0.0.1:{port}/metrics) so the antivirus can be scraped by an external
// observability stack without any Windows-specific agent.
public interface IMetricsExporter
{
    Task StartAsync(int port, CancellationToken ct = default);
    void Stop();
    Task<string> BuildPrometheusTextAsync(CancellationToken ct = default);
}
