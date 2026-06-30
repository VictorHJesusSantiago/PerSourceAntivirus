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
public sealed class LlmnrPoisoningDetector(IServiceScopeFactory scopeFactory) : ILlmnrPoisoningDetector
{
    // query name → (querierIp, list of (responderIp, mac, seenAt))
    private readonly ConcurrentDictionary<string, (string querierIp, List<(string ip, string mac, DateTime seen)> responders)> _queryMap = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    public event EventHandler<LlmnrPoisoningAlertEventArgs>? AlertDetected;

    private const int LlmnrPort = 5355;
    private const int NbnsPort  = 137;
    private const int MdnsPort  = 5353;

    public async Task StartMonitoringAsync(string? deviceName, CancellationToken ct)
    {
        _running = true;
        ILiveDevice? device = null;
        try
        {
            device = GetDevice(deviceName);
            if (device is null) return;

            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.Filter = $"udp port {LlmnrPort} or udp port {NbnsPort} or udp port {MdnsPort}";
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
            var ip  = packet.Extract<IPPacket>();
            var udp = packet.Extract<UdpPacket>();
            if (ip is null || udp?.PayloadData is null) return;

            var srcIp  = ip.SourceAddress.ToString();
            var srcMac = ExtractSrcMac(packet);
            var port   = udp.DestinationPort;

            string proto = port switch
            {
                LlmnrPort => "LLMNR",
                NbnsPort  => "NBNS",
                MdnsPort  => "MDNS",
                _         => "Unknown"
            };

            var payload = udp.PayloadData;
            if (payload.Length < 12) return;

            bool isResponse = (payload[2] & 0x80) != 0; // QR bit
            var queryName = ParseDnsName(payload, 12);
            if (string.IsNullOrEmpty(queryName)) return;

            var now = DateTime.UtcNow;

            if (!isResponse)
            {
                // It's a query — record querier
                _queryMap[queryName] = (srcIp, []);
            }
            else
            {
                // It's a response — check if multiple responders
                if (!_queryMap.TryGetValue(queryName, out var entry)) return;

                var responders = entry.responders;
                lock (responders)
                {
                    responders.RemoveAll(r => (now - r.seen).TotalSeconds > 30);
                    if (!responders.Any(r => r.ip == srcIp))
                        responders.Add((srcIp, srcMac, now));

                    if (responders.Count > 1)
                    {
                        // Multiple distinct IPs responding to same query = poisoning
                        var spoofed = responders.Last().ip;
                        FireAlert(proto, queryName, entry.querierIp, srcIp, srcMac, spoofed, "MultipleResponders");
                    }
                }
            }
        }
        catch { }
    }

    private void FireAlert(string proto, string queryName, string querierIp, string responderIp,
        string responderMac, string spoofedIp, string reason)
    {
        var key = $"{proto}_{queryName}_{responderIp}";
        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 5) return;
        _recentAlerts[key] = now;

        var alert = new LlmnrPoisoningAlert
        {
            Id = Guid.NewGuid(),
            Protocol = proto,
            QueryName = queryName,
            QuerierIp = querierIp,
            ResponderIp = responderIp,
            ResponderMac = responderMac,
            SpoofedIp = spoofedIp,
            DetectionReason = reason,
            Severity = 8,
            DetectedAtUtc = now
        };

        _ = PersistAsync(alert);
        AlertDetected?.Invoke(this, new LlmnrPoisoningAlertEventArgs(alert));
    }

    // Per-write scope: AppDbContext is not thread-safe; these run on capture-callback threads.
    private async Task PersistAsync(LlmnrPoisoningAlert alert)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<ILlmnrPoisoningAlertRepository>();
            await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
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

    private static string ExtractSrcMac(Packet packet)
    {
        try
        {
            var eth = packet.Extract<EthernetPacket>();
            return eth?.SourceHardwareAddress?.ToString() ?? "unknown";
        }
        catch { return "unknown"; }
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
