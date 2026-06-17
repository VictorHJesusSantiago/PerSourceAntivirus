using System.Runtime.CompilerServices;
using System.Threading.Channels;
using PacketDotNet;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Enums;
using SharpPcap;

namespace PerSourceAntivirus.Infrastructure.Network;

public class SharpPcapNetworkMonitor : INetworkMonitor
{
    public IReadOnlyList<CaptureDeviceInfo> GetAvailableDevices()
    {
        try
        {
            return CaptureDeviceList.Instance
                .Select(device => new CaptureDeviceInfo(device.Name, device.Description ?? string.Empty))
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    public async IAsyncEnumerable<CapturedPacket> CaptureAsync(
        string? deviceName,
        TimeSpan duration,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ICaptureDevice? device = GetDevice(deviceName);
        if (device is null)
        {
            yield break;
        }

        if (!TryOpenDevice(device))
        {
            yield break;
        }

        var channel = Channel.CreateUnbounded<CapturedPacket>();

        void OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket is null)
            {
                return;
            }

            var protocol = NetworkProtocol.Other;
            var sourcePort = 0;
            var destinationPort = 0;

            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket is not null)
            {
                protocol = NetworkProtocol.Tcp;
                sourcePort = tcpPacket.SourcePort;
                destinationPort = tcpPacket.DestinationPort;
            }
            else
            {
                var udpPacket = packet.Extract<UdpPacket>();
                if (udpPacket is not null)
                {
                    protocol = NetworkProtocol.Udp;
                    sourcePort = udpPacket.SourcePort;
                    destinationPort = udpPacket.DestinationPort;
                }
            }

            channel.Writer.TryWrite(new CapturedPacket(
                protocol,
                ipPacket.SourceAddress.ToString(),
                sourcePort,
                ipPacket.DestinationAddress.ToString(),
                destinationPort,
                rawPacket.Data.Length));
        }

        device.OnPacketArrival += OnPacketArrival;
        device.StartCapture();

        // Complete the channel after duration so ReadAllAsync returns naturally without throwing.
        using var timeoutCts = new CancellationTokenSource(duration);
        timeoutCts.Token.Register(() => channel.Writer.TryComplete());
        cancellationToken.Register(() => channel.Writer.TryComplete());

        try
        {
            await foreach (var capturedPacket in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yield return capturedPacket;
            }
        }
        finally
        {
            device.OnPacketArrival -= OnPacketArrival;
            device.StopCapture();
            device.Close();
        }
    }

    private static ICaptureDevice? GetDevice(string? deviceName)
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            return deviceName is not null
                ? devices.FirstOrDefault(d => d.Name == deviceName)
                : devices.FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    private static bool TryOpenDevice(ICaptureDevice device)
    {
        try
        {
            device.Open(DeviceModes.Promiscuous, 1000);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
