using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class SharpPcapIdsDetector(INetworkIdsAlertRepository repository) : INetworkIdsDetector
{
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    public event EventHandler<NetworkIdsAlertEventArgs>? AlertDetected;

    // EternalBlue: SMBv1 TRANS2 exploit pattern at start of SMB payload
    private static readonly byte[] PatternEternalBlue = [0xFF, 0x53, 0x4D, 0x42]; // \xFF SMB signature

    // Log4Shell: jndi: prefix in HTTP payload (ASCII)
    private static readonly byte[] PatternLog4Shell = Encoding.ASCII.GetBytes("${jndi:");

    // Log4Shell variant: jndi:ldap (lowercased check done separately)
    private static readonly byte[] PatternLog4ShellLdap = Encoding.ASCII.GetBytes("jndi:ldap://");

    // Heartbleed: TLS heartbeat record type 0x18
    private const byte TlsHeartbeatType = 0x18;

    // BlueKeep: TPKT + COTP connection request cookie
    private static readonly byte[] PatternBlueKeep = [0x03, 0x00]; // TPKT header

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

            var tcp = packet.Extract<TcpPacket>();
            if (tcp?.PayloadData is { Length: > 0 } tcpPayload)
            {
                CheckEternalBlue(ip, tcp, tcpPayload);
                CheckLog4Shell(ip, tcp, tcpPayload);
                CheckBlueKeep(ip, tcp, tcpPayload);
                CheckHeartbleed(ip, tcp, tcpPayload);
            }
        }
        catch { }
    }

    private void CheckEternalBlue(IPPacket ip, TcpPacket tcp, byte[] payload)
    {
        if (tcp.DestinationPort != 445 && tcp.SourcePort != 445) return;
        if (payload.Length < 8) return;

        // Look for SMB header signature \xFF SMB or SMBv2 \xFE SMB
        for (int i = 0; i <= payload.Length - 4; i++)
        {
            if ((payload[i] == 0xFF || payload[i] == 0xFE) &&
                payload[i + 1] == 0x53 && payload[i + 2] == 0x4D && payload[i + 3] == 0x42)
            {
                // Check for suspicious SMB command (0x25 = TRANS2, exploit indicator)
                bool suspicious = payload.Length > i + 4 && payload[i + 4] == 0x25;
                if (!suspicious && payload[i] == 0xFF) suspicious = true; // SMBv1 at all is flagged

                if (suspicious)
                {
                    FireAlert("EternalBlue", ip.SourceAddress.ToString(), tcp.SourcePort,
                        ip.DestinationAddress.ToString(), tcp.DestinationPort, "TCP",
                        BitConverter.ToString(payload, i, Math.Min(8, payload.Length - i)),
                        payload.Length,
                        "SMBv1 exploit pattern (MS17-010 / EternalBlue)", 9);
                    return;
                }
            }
        }
    }

    private void CheckLog4Shell(IPPacket ip, TcpPacket tcp, byte[] payload)
    {
        if (tcp.DestinationPort != 80 && tcp.DestinationPort != 8080 &&
            tcp.DestinationPort != 443 && tcp.DestinationPort != 8443) return;

        var payloadStr = Encoding.UTF8.GetString(payload);
        var payloadLower = payloadStr.ToLowerInvariant();

        bool found = payloadLower.Contains("${jndi:") ||
                     payloadLower.Contains("jndi:ldap://") ||
                     payloadLower.Contains("jndi:rmi://") ||
                     payloadLower.Contains("jndi:dns://");

        if (found)
        {
            int idx = payloadLower.IndexOf("jndi:", StringComparison.Ordinal);
            if (idx < 0) idx = 0;
            var matchBytes = Encoding.UTF8.GetBytes(payloadStr[idx..Math.Min(idx + 20, payloadStr.Length)]);

            FireAlert("Log4Shell", ip.SourceAddress.ToString(), tcp.SourcePort,
                ip.DestinationAddress.ToString(), tcp.DestinationPort, "HTTP",
                BitConverter.ToString(matchBytes),
                payload.Length,
                "Log4Shell JNDI injection pattern (CVE-2021-44228)", 10);
        }
    }

    private void CheckHeartbleed(IPPacket ip, TcpPacket tcp, byte[] payload)
    {
        if (tcp.DestinationPort != 443 && tcp.SourcePort != 443) return;
        if (payload.Length < 5) return;

        // TLS record layer: ContentType(1) + Version(2) + Length(2) + ...
        // Heartbeat type = 0x18
        if (payload[0] == TlsHeartbeatType && payload.Length >= 7)
        {
            // Heartbeat message: Type(1) + Length(2)
            // Heartbleed: payload length > 16384 bytes (0x4000)
            int heartbeatPayloadLength = (payload[5] << 8) | payload[6];
            if (heartbeatPayloadLength > 16384)
            {
                FireAlert("Heartbleed", ip.SourceAddress.ToString(), tcp.SourcePort,
                    ip.DestinationAddress.ToString(), tcp.DestinationPort, "TLS",
                    BitConverter.ToString(payload, 0, Math.Min(7, payload.Length)),
                    payload.Length,
                    $"TLS Heartbeat with oversized payload {heartbeatPayloadLength} bytes (CVE-2014-0160)", 9);
            }
        }
    }

    private void CheckBlueKeep(IPPacket ip, TcpPacket tcp, byte[] payload)
    {
        if (tcp.DestinationPort != 3389 && tcp.SourcePort != 3389) return;
        if (payload.Length < 11) return;

        // TPKT: 0x03 0x00 <length_hi> <length_lo>
        // COTP CR (Connection Request): 0xE0
        if (payload[0] == 0x03 && payload[1] == 0x00 && payload.Length > 4 && payload[4] == 0xE0)
        {
            // Check for mstshash cookie (BlueKeep pre-auth exploit signature)
            var payloadStr = Encoding.ASCII.GetString(payload);
            if (payloadStr.Contains("Microsof") || payloadStr.Contains("mstshash="))
            {
                FireAlert("BlueKeep", ip.SourceAddress.ToString(), tcp.SourcePort,
                    ip.DestinationAddress.ToString(), tcp.DestinationPort, "RDP",
                    BitConverter.ToString(payload, 0, Math.Min(11, payload.Length)),
                    payload.Length,
                    "BlueKeep RDP pre-auth exploit pattern (CVE-2019-0708)", 9);
            }
        }
    }

    private void FireAlert(string sigName, string srcIp, int srcPort, string dstIp, int dstPort,
        string proto, string matchedBytes, int payloadLen, string description, int severity)
    {
        var key = $"{srcIp}:{dstIp}:{sigName}";
        var now = DateTime.UtcNow;

        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 5)
            return;
        _recentAlerts[key] = now;

        var alert = new NetworkIntrusionAlert
        {
            Id = Guid.NewGuid(),
            SignatureName = sigName,
            SourceIp = srcIp,
            SourcePort = srcPort,
            DestinationIp = dstIp,
            DestinationPort = dstPort,
            Protocol = proto,
            MatchedPattern = matchedBytes,
            PayloadLength = payloadLen,
            Description = description,
            Severity = severity,
            DetectedAtUtc = now
        };

        try { repository.AddAsync(alert).GetAwaiter().GetResult(); } catch { }
        AlertDetected?.Invoke(this, new NetworkIdsAlertEventArgs(alert));
    }

    private static ILiveDevice? GetDevice(string? deviceName)
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0) return null;
            if (deviceName is not null)
                return devices.FirstOrDefault(d => d.Name == deviceName || d.Description?.Contains(deviceName, StringComparison.OrdinalIgnoreCase) == true);
            return devices[0];
        }
        catch { return null; }
    }
}
