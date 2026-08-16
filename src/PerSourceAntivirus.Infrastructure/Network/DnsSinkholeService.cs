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

        if (await TryStartLocalProxyAsync(ct))
            return;

        await StartSharpPcapModeAsync(deviceName, ct);
    }

    public void Stop() => _running = false;


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
            return false;
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

        if ((query[2] & 0x80) != 0) return;

        var domain = ParseDnsName(query, 12);
        if (string.IsNullOrEmpty(domain)) return;

        if (domainBlocklist.IsSuspiciousDomain(domain, out _))
        {
            var txId = (ushort)((query[0] << 8) | query[1]);
            var response = BuildSinkholeResponse(txId, domain);
            try { listener.Send(response, response.Length, client); } catch { }
            RequestSinkholed?.Invoke(this, new DnsSinkholeEventArgs(domain, client.Address.ToString(), client.Port, SinkholeIp));
            return;
        }

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
        bw.Write((byte)(txId >> 8)); bw.Write((byte)(txId & 0xFF));
        bw.Write((byte)0x81); bw.Write((byte)0x80);
        bw.Write((byte)0x00); bw.Write((byte)0x01);
        bw.Write((byte)0x00); bw.Write((byte)0x01);
        bw.Write((byte)0x00); bw.Write((byte)0x00);
        bw.Write((byte)0x00); bw.Write((byte)0x00);
        foreach (var label in domain.Split('.'))
        {
            var lb = Encoding.ASCII.GetBytes(label);
            bw.Write((byte)lb.Length);
            bw.Write(lb);
        }
        bw.Write((byte)0x00);
        bw.Write((byte)0x00); bw.Write((byte)0x01);
        bw.Write((byte)0x00); bw.Write((byte)0x01);
        bw.Write((byte)0xC0); bw.Write((byte)0x0C);
        bw.Write((byte)0x00); bw.Write((byte)0x01);
        bw.Write((byte)0x00); bw.Write((byte)0x01);
        bw.Write((byte)0x00); bw.Write((byte)0x00); bw.Write((byte)0x00); bw.Write((byte)0x3C);
        bw.Write((byte)0x00); bw.Write((byte)0x04);
        bw.Write((byte)127); bw.Write((byte)0); bw.Write((byte)0); bw.Write((byte)1);
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
