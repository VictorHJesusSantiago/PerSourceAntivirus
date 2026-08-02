using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Reporting;

public sealed class PrometheusMetricsExporter(
    IServiceScopeFactory scopeFactory,
    IDetectorDiagnostics detectorDiagnostics) : IMetricsExporter, IDisposable
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

        AppendDetectorHealth(sb);

        return sb.ToString();
    }

    // [ADR-001] RED metrics per detector. Alert counters alone cannot distinguish "no threats
    // found" from "detector dead": these expose the scan rate, error rate and duration that make
    // a stalled or permanently-failing detector visible to alerting.
    private void AppendDetectorHealth(StringBuilder sb)
    {
        var snapshot = detectorDiagnostics.GetHealthSnapshot();

        sb.AppendLine("# HELP psav_detector_scans_total Completed scan iterations per detector");
        sb.AppendLine("# TYPE psav_detector_scans_total counter");
        foreach (var d in snapshot)
            sb.AppendLine($"psav_detector_scans_total{{detector=\"{Escape(d.DetectorName)}\"}} {d.ScansCompleted}");

        sb.AppendLine("# HELP psav_detector_errors_total Failed scan iterations per detector");
        sb.AppendLine("# TYPE psav_detector_errors_total counter");
        foreach (var d in snapshot)
            sb.AppendLine($"psav_detector_errors_total{{detector=\"{Escape(d.DetectorName)}\"}} {d.ScansFailed}");

        sb.AppendLine("# HELP psav_detector_last_scan_duration_seconds Duration of the most recent successful scan");
        sb.AppendLine("# TYPE psav_detector_last_scan_duration_seconds gauge");
        foreach (var d in snapshot)
            sb.AppendLine($"psav_detector_last_scan_duration_seconds{{detector=\"{Escape(d.DetectorName)}\"}} {d.LastScanDurationSeconds.ToString("F4", CultureInfo.InvariantCulture)}");

        // Age of the last success is the key liveness signal: alert when it stops advancing.
        sb.AppendLine("# HELP psav_detector_seconds_since_last_success Seconds since the detector last completed a scan");
        sb.AppendLine("# TYPE psav_detector_seconds_since_last_success gauge");
        var now = DateTime.UtcNow;
        foreach (var d in snapshot)
        {
            var seconds = d.LastSuccessfulScanUtc is { } last ? (now - last).TotalSeconds : -1;
            sb.AppendLine($"psav_detector_seconds_since_last_success{{detector=\"{Escape(d.DetectorName)}\"}} {seconds.ToString("F0", CultureInfo.InvariantCulture)}");
        }
    }

    private static string Escape(string label) => label.Replace("\\", "\\\\").Replace("\"", "\\\"");

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
