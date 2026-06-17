using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INetworkMonitor
{
    IReadOnlyList<CaptureDeviceInfo> GetAvailableDevices();

    IAsyncEnumerable<CapturedPacket> CaptureAsync(string? deviceName, TimeSpan duration, CancellationToken cancellationToken = default);
}

public record CaptureDeviceInfo(string Name, string Description);

public record CapturedPacket(
    NetworkProtocol Protocol,
    string SourceAddress,
    int SourcePort,
    string DestinationAddress,
    int DestinationPort,
    int Length);
