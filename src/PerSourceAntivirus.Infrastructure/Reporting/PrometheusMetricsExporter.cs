using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Reporting;

public sealed class PrometheusMetricsExporter(IServiceScopeFactory scopeFactory) : IMetricsExporter, IDisposable
{
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;

    public Task StartAsync(int port, CancellationToken ct = default)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/metrics/");
        _listener.Start();

        _loopTask = Task.Run(() => AcceptLoopAsync(_cts.Token), CancellationToken.None);
        return Task.CompletedTask;
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is { IsListening: true })
        {
            HttpListenerContext context;
            try { context = await _listener.GetContextAsync().WaitAsync(ct).ConfigureAwait(false); }
            catch (Exception) { break; }

            try
            {
                var body = await BuildPrometheusTextAsync(ct).ConfigureAwait(false);
                var bytes = Encoding.UTF8.GetBytes(body);
                context.Response.ContentType = "text/plain; version=0.0.4";
                context.Response.ContentLength64 = bytes.Length;
                await context.Response.OutputStream.WriteAsync(bytes, ct).ConfigureAwait(false);
            }
            catch { }
            finally
            {
                try { context.Response.Close(); } catch { }
            }
        }
    }

    public async Task<string> BuildPrometheusTextAsync(CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var sb = new StringBuilder();

        sb.AppendLine("# HELP psav_scanned_files_total Total files scanned, by threat status");
        sb.AppendLine("# TYPE psav_scanned_files_total counter");
        foreach (ThreatStatus status in Enum.GetValues<ThreatStatus>())
        {
            var count = await db.ScannedFiles.CountAsync(f => f.ThreatStatus == status, ct).ConfigureAwait(false);
            sb.AppendLine($"psav_scanned_files_total{{status=\"{status}\"}} {count}");
        }

        await AppendAlertCountAsync<RansomwareAlert>(sb, db, "ransomware", ct);
        await AppendAlertCountAsync<HeapSprayAlert>(sb, db, "heap_spray", ct);
        await AppendAlertCountAsync<ProcessHollowingAlert>(sb, db, "process_hollowing", ct);
        await AppendAlertCountAsync<LolBinAlert>(sb, db, "lolbin", ct);
        await AppendAlertCountAsync<FilelessAlert>(sb, db, "fileless", ct);
        await AppendAlertCountAsync<KeyloggerDetectionAlert>(sb, db, "keylogger", ct);
        await AppendAlertCountAsync<ClipboardHijackAlert>(sb, db, "clipboard_hijack", ct);
        await AppendAlertCountAsync<NetworkIntrusionAlert>(sb, db, "network_ids", ct);
        await AppendAlertCountAsync<ArpSpoofingAlert>(sb, db, "arp_spoofing", ct);
        await AppendAlertCountAsync<DllHijackAlert>(sb, db, "dll_hijack", ct);
        await AppendAlertCountAsync<CryptojackingAlert>(sb, db, "cryptojacking", ct);
        await AppendAlertCountAsync<UnsignedBinaryAlert>(sb, db, "unsigned_binary", ct);
        await AppendAlertCountAsync<CertificateTrustAlert>(sb, db, "certificate_blacklist", ct);
        await AppendAlertCountAsync<DnsTunnelingAlert>(sb, db, "dns_tunneling", ct);
        await AppendAlertCountAsync<GeoIpBlockAlert>(sb, db, "geoip_block", ct);
        await AppendAlertCountAsync<UsbDeviceEvent>(sb, db, "usb_device_event", ct);

        return sb.ToString();
    }

    private static async Task AppendAlertCountAsync<T>(StringBuilder sb, AppDbContext db, string metricSuffix, CancellationToken ct)
        where T : class
    {
        var count = await db.Set<T>().CountAsync(ct).ConfigureAwait(false);
        sb.AppendLine($"# HELP psav_alerts_{metricSuffix}_total Total {metricSuffix} alerts recorded");
        sb.AppendLine($"# TYPE psav_alerts_{metricSuffix}_total counter");
        sb.AppendLine($"psav_alerts_{metricSuffix}_total {count}");
    }

    public void Dispose()
    {
        Stop();
        _listener?.Close();
    }
}
