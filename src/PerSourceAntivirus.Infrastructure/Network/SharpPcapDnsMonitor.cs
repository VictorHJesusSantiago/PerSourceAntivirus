using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Channels;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

public class SharpPcapDnsMonitor(IDomainBlocklist domainBlocklist) : IDnsMonitor
{
    public async IAsyncEnumerable<DnsQueryData> WatchAsync(
        string? deviceName = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ILiveDevice? device = null;
        try
        {
            device = GetDevice(deviceName);
        }
        catch (Exception) { yield break; }

        if (device is null) yield break;

        var channel = Channel.CreateUnbounded<DnsQueryData>();
        cancellationToken.Register(() => channel.Writer.TryComplete());

        device.OnPacketArrival += (_, e) =>
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var ip = packet.Extract<IPPacket>();
            var udp = packet.Extract<UdpPacket>();
            if (ip is null || udp is null || udp.DestinationPort != 53) return;

            var (queryName, queryType) = ParseDnsQuery(udp.PayloadData);
            if (queryName is null) return;

            domainBlocklist.IsSuspiciousDomain(queryName, out var reason);
            channel.Writer.TryWrite(new DnsQueryData(queryName, queryType, ip.SourceAddress.ToString(), reason is not null, reason));
        };

        try
        {
            device.Open(DeviceModes.Promiscuous, 1000);
            device.StartCapture();

            await foreach (var query in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yield return query;
            }
        }
        finally
        {
            try { device.StopCapture(); } catch { }
            device.Close();
        }
    }

    private static ILiveDevice? GetDevice(string? deviceName)
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0) return null;

        if (deviceName is not null)
            return devices.FirstOrDefault(d => d.Name == deviceName);

        return devices[0];
    }

    private static (string? QueryName, string QueryType) ParseDnsQuery(byte[] payload)
    {
        if (payload is null || payload.Length < 13) return (null, "");

        // Bit 15 of flags = QR: 0 = query, 1 = response.
        var flags = (ushort)((payload[2] << 8) | payload[3]);
        if ((flags & 0x8000) != 0) return (null, "");

        var questionCount = (payload[4] << 8) | payload[5];
        if (questionCount == 0) return (null, "");

        var labels = new List<string>();
        var i = 12;
        while (i < payload.Length)
        {
            var len = payload[i++];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) { i++; break; } // compression pointer
            if (i + len > payload.Length) return (null, "");
            labels.Add(Encoding.ASCII.GetString(payload, i, len));
            i += len;
        }

        var name = labels.Count > 0 ? string.Join(".", labels) : null;

        var qtype = (i + 1 < payload.Length) ? (payload[i] << 8) | payload[i + 1] : 0;
        var qtypeStr = qtype switch
        {
            1 => "A", 2 => "NS", 5 => "CNAME", 12 => "PTR",
            15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV",
            255 => "ANY", _ => qtype.ToString()
        };

        return (name, qtypeStr);
    }
}
