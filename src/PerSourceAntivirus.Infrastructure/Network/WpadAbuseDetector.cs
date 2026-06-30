using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class WpadAbuseDetector(IServiceScopeFactory scopeFactory) : IWpadAbuseDetector
{
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts =
        new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _running;

    public event EventHandler<WpadAbuseAlertEventArgs>? AlertDetected;

    private const string BpfFilter = "udp port 53 or tcp port 80";
    private const double DedupMinutes = 5.0;

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        ILiveDevice? device = null;
        try
        {
            device = GetDevice(null);
            if (device is null) return;

            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.Filter = BpfFilter;
            device.StartCapture();

            while (_running && !ct.IsCancellationRequested)
                await Task.Delay(500, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (device is not null)
            {
                try { device.StopCapture(); } catch { }
                device.OnPacketArrival -= OnPacketArrival;
                device.Close();
            }
            _running = false;
        }
    }

    public void StopMonitoring() => _running = false;

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ip = packet.Extract<IPPacket>();
            if (ip is null) return;

            var srcIp = ip.SourceAddress.ToString();

            var udp = packet.Extract<UdpPacket>();
            if (udp is not null && udp.DestinationPort == 53)
            {
                HandleDnsPacket(udp.PayloadData, srcIp);
                return;
            }

            var tcp = packet.Extract<TcpPacket>();
            if (tcp is not null && (tcp.DestinationPort == 80 || tcp.SourcePort == 80))
            {
                HandleHttpPacket(tcp.PayloadData, srcIp, ip.DestinationAddress.ToString());
            }
        }
        catch { }
    }

    private void HandleDnsPacket(byte[]? payload, string srcIp)
    {
        if (payload is null || payload.Length < 12) return;
        try
        {
            bool isQuery = (payload[2] & 0x80) == 0;
            if (!isQuery) return;

            var queriedName = ParseDnsName(payload, 12);
            if (string.IsNullOrEmpty(queriedName)) return;

            if (!queriedName.StartsWith("wpad", StringComparison.OrdinalIgnoreCase)) return;

            FireAlert("DNS", queriedName, srcIp, string.Empty, $"DNS query for WPAD hostname: {queriedName}");
        }
        catch { }
    }

    private void HandleHttpPacket(byte[]? payload, string srcIp, string dstIp)
    {
        if (payload is null || payload.Length < 4) return;
        try
        {
            var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 4096));

            if (text.StartsWith("GET ", StringComparison.OrdinalIgnoreCase) &&
                text.Contains("/wpad.dat", StringComparison.OrdinalIgnoreCase))
            {
                var hostHeader = ExtractHttpHeader(text, "Host");
                var hostname = string.IsNullOrEmpty(hostHeader) ? dstIp : hostHeader;
                FireAlert("HTTP", hostname, srcIp, string.Empty, $"HTTP GET /wpad.dat request detected from {srcIp}");
                return;
            }

            // Check if this is a response to a wpad.dat request (HTTP 200 with body)
            if (text.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) &&
                text.Contains("200 OK", StringComparison.OrdinalIgnoreCase))
            {
                var bodyStart = FindBodyStart(text);
                if (bodyStart >= 0)
                {
                    var body = text[bodyStart..];
                    if (body.Contains("FindProxyForURL", StringComparison.OrdinalIgnoreCase))
                    {
                        var truncatedBody = body.Length > 512 ? body[..512] : body;
                        FireAlert("HTTP", srcIp, srcIp, truncatedBody,
                            $"WPAD PAC file response detected from {srcIp} (FindProxyForURL)");
                    }
                }
            }
        }
        catch { }
    }

    private static string ExtractHttpHeader(string text, string headerName)
    {
        var prefix = headerName + ":";
        var lines = text.Split('\n');
        foreach (var line in lines)
        {
            if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return line[prefix.Length..].Trim().TrimEnd('\r');
        }
        return string.Empty;
    }

    private static int FindBodyStart(string text)
    {
        var idx = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (idx >= 0) return idx + 4;
        idx = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (idx >= 0) return idx + 2;
        return -1;
    }

    private static string ParseDnsName(byte[] data, int offset)
    {
        var labels = new List<string>();
        int i = offset;
        while (i < data.Length)
        {
            int len = data[i++];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) { i++; break; }
            if (i + len > data.Length) break;
            labels.Add(Encoding.ASCII.GetString(data, i, len));
            i += len;
        }
        return labels.Count > 0 ? string.Join(".", labels) : string.Empty;
    }

    private void FireAlert(string queryType, string hostname, string responderIp, string wpadDatContent, string reason)
    {
        var key = $"{queryType}_{hostname}_{responderIp}";
        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < DedupMinutes) return;
        _recentAlerts[key] = now;

        var alert = new WpadAbuseAlert
        {
            Id = Guid.NewGuid(),
            QueryType = queryType,
            Hostname = hostname,
            ResponderIp = responderIp,
            WpadDatContent = wpadDatContent,
            DetectionReason = reason,
            Severity = 7,
            DetectedAtUtc = now
        };

        _ = PersistAsync(alert);
        AlertDetected?.Invoke(this, new WpadAbuseAlertEventArgs(alert));
    }

    // Per-write scope: AppDbContext is not thread-safe; these run on capture-callback threads.
    private async Task PersistAsync(WpadAbuseAlert alert)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IWpadAbuseAlertRepository>();
            await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
    }

    private static ILiveDevice? GetDevice(string? deviceName)
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0) return null;
            if (deviceName is not null)
                return devices.FirstOrDefault(d => d.Name == deviceName);
            return devices[0];
        }
        catch { return null; }
    }
}
