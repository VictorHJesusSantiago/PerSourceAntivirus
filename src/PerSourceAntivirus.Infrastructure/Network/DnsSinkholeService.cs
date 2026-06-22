using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class DnsSinkholeService(IDomainBlocklist domainBlocklist) : IDnsSinkhole
{
    private volatile bool _running;
    private const string SinkholeIp = "127.0.0.1";
    private static readonly IPEndPoint UpstreamDns = new(IPAddress.Parse("8.8.8.8"), 53);

    public event EventHandler<DnsSinkholeEventArgs>? RequestSinkholed;

    public async Task StartAsync(string? deviceName, CancellationToken ct)
    {
        _running = true;

        // Primary mode: bind a local UDP listener on 127.0.0.1:53 (requires admin).
        // This is a true DNS proxy — no race condition, no Npcap dependency.
        // Falls back to SharpPcap promiscuous-capture mode if port 53 bind fails.
        if (await TryStartLocalProxyAsync(ct))
            return;

        await StartSharpPcapModeAsync(deviceName, ct);
    }

    public void Stop() => _running = false;

    // ──────────────────────────────────────────────────────────────────────────
    // Mode 1: Local UDP DNS proxy on 127.0.0.1:53
    // ──────────────────────────────────────────────────────────────────────────

    private async Task<bool> TryStartLocalProxyAsync(CancellationToken ct)
    {
        UdpClient? listener = null;
        try
        {
            listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53));
        }
        catch
        {
            listener?.Dispose();
            return false; // port 53 not available — try SharpPcap
        }

        try
        {
            await RunLocalProxyLoopAsync(listener, ct);
            return true;
        }
        finally
        {
            listener.Dispose();
            _running = false;
        }
    }

    private async Task RunLocalProxyLoopAsync(UdpClient listener, CancellationToken ct)
    {
        while (_running && !ct.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await listener.ReceiveAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch { continue; }

            _ = Task.Run(() => HandleProxyQuery(listener, result.Buffer, result.RemoteEndPoint), ct);
        }
    }

    private void HandleProxyQuery(UdpClient listener, byte[] query, IPEndPoint client)
    {
        if (query.Length < 12) return;

        // Only handle DNS queries (QR bit = 0)
        if ((query[2] & 0x80) != 0) return;

        var domain = ParseDnsName(query, 12);
        if (string.IsNullOrEmpty(domain)) return;

        if (domainBlocklist.IsSuspiciousDomain(domain, out _))
        {
            // Return sinkhole response pointing to 127.0.0.1
            var txId = (ushort)((query[0] << 8) | query[1]);
            var response = BuildSinkholeResponse(txId, domain);
            try { listener.Send(response, response.Length, client); } catch { }
            RequestSinkholed?.Invoke(this, new DnsSinkholeEventArgs(domain, client.Address.ToString(), client.Port, SinkholeIp));
            return;
        }

        // Forward clean query to upstream DNS and relay response
        try
        {
            using var upstream = new UdpClient();
            upstream.Connect(UpstreamDns);
            upstream.Send(query, query.Length);
            upstream.Client.ReceiveTimeout = 3000;
            var remoteAny = new IPEndPoint(IPAddress.Any, 0);
            var response = upstream.Receive(ref remoteAny);
            listener.Send(response, response.Length, client);
        }
        catch { }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Mode 2: SharpPcap promiscuous capture (fallback — requires Npcap)
    // ──────────────────────────────────────────────────────────────────────────

    private async Task StartSharpPcapModeAsync(string? deviceName, CancellationToken ct)
    {
        ILiveDevice? device = null;
        try
        {
            device = GetDevice(deviceName);
            if (device is null) return;

            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.Filter = "udp port 53";
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

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw    = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ip     = packet.Extract<IPPacket>();
            var udp    = packet.Extract<UdpPacket>();
            if (ip is null || udp?.PayloadData is null) return;
            if (udp.DestinationPort != 53) return;
            var payload = udp.PayloadData;
            if (payload.Length < 12 || (payload[2] & 0x80) != 0) return;

            var queryName = ParseDnsName(payload, 12);
            if (string.IsNullOrEmpty(queryName)) return;
            if (!domainBlocklist.IsSuspiciousDomain(queryName, out _)) return;

            var srcIp   = ip.SourceAddress.ToString();
            var srcPort = udp.SourcePort;
            var txId    = (ushort)((payload[0] << 8) | payload[1]);

            SendSharpPcapSinkholeResponse(srcIp, srcPort, txId, queryName);
            RequestSinkholed?.Invoke(this, new DnsSinkholeEventArgs(queryName, srcIp, srcPort, SinkholeIp));
        }
        catch { }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Shared helpers
    // ──────────────────────────────────────────────────────────────────────────

    private static byte[] BuildSinkholeResponse(ushort txId, string domain)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        WriteDnsResponse(bw, txId, domain);
        return ms.ToArray();
    }

    private static void SendSharpPcapSinkholeResponse(string dstIp, int dstPort, ushort txId, string queryName)
    {
        try
        {
            var bytes = BuildSinkholeResponse(txId, queryName);
            using var udpClient = new UdpClient();
            udpClient.Send(bytes, bytes.Length, dstIp, dstPort);
        }
        catch { }
    }

    private static void WriteDnsResponse(BinaryWriter bw, ushort txId, string domain)
    {
        // Header
        bw.Write((byte)(txId >> 8)); bw.Write((byte)(txId & 0xFF));
        bw.Write((byte)0x81); bw.Write((byte)0x80); // QR=1, RD=1, RA=1, NOERROR
        bw.Write((byte)0x00); bw.Write((byte)0x01); // QDCOUNT=1
        bw.Write((byte)0x00); bw.Write((byte)0x01); // ANCOUNT=1
        bw.Write((byte)0x00); bw.Write((byte)0x00); // NSCOUNT=0
        bw.Write((byte)0x00); bw.Write((byte)0x00); // ARCOUNT=0
        // Question
        foreach (var label in domain.Split('.'))
        {
            var lb = Encoding.ASCII.GetBytes(label);
            bw.Write((byte)lb.Length);
            bw.Write(lb);
        }
        bw.Write((byte)0x00);
        bw.Write((byte)0x00); bw.Write((byte)0x01); // QTYPE  A
        bw.Write((byte)0x00); bw.Write((byte)0x01); // QCLASS IN
        // Answer — pointer to question name
        bw.Write((byte)0xC0); bw.Write((byte)0x0C);
        bw.Write((byte)0x00); bw.Write((byte)0x01); // TYPE  A
        bw.Write((byte)0x00); bw.Write((byte)0x01); // CLASS IN
        bw.Write((byte)0x00); bw.Write((byte)0x00); bw.Write((byte)0x00); bw.Write((byte)0x3C); // TTL 60
        bw.Write((byte)0x00); bw.Write((byte)0x04); // RDLENGTH 4
        bw.Write((byte)127); bw.Write((byte)0); bw.Write((byte)0); bw.Write((byte)1); // 127.0.0.1
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

    private static ILiveDevice? GetDevice(string? deviceName)
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0) return null;
            return deviceName is not null
                ? devices.FirstOrDefault(d => d.Name == deviceName)
                : devices[0];
        }
        catch { return null; }
    }
}
