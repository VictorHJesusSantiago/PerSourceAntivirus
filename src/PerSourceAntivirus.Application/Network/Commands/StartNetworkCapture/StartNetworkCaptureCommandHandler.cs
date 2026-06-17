using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Commands.StartNetworkCapture;

public class StartNetworkCaptureCommandHandler(
    INetworkMonitor networkMonitor,
    IBlocklistProvider blocklistProvider,
    INetworkConnectionEventRepository connectionEventRepository)
    : IRequestHandler<StartNetworkCaptureCommand, StartNetworkCaptureResult>
{
    public async Task<StartNetworkCaptureResult> Handle(StartNetworkCaptureCommand request, CancellationToken cancellationToken)
    {
        var startedAt = DateTime.UtcNow;
        var packetsCaptured = 0;
        var blocklistedCount = 0;
        var events = new List<NetworkConnectionEvent>();

        var duration = TimeSpan.FromSeconds(request.DurationSeconds);
        await foreach (var packet in networkMonitor.CaptureAsync(request.DeviceName, duration, cancellationToken))
        {
            var sourceBlocked = blocklistProvider.TryGetBlockReason(packet.SourceAddress, out var sourceReason);
            var destinationBlocked = blocklistProvider.TryGetBlockReason(packet.DestinationAddress, out var destinationReason);
            var isBlocklisted = sourceBlocked || destinationBlocked;

            if (isBlocklisted)
            {
                blocklistedCount++;
            }

            events.Add(new NetworkConnectionEvent
            {
                Id = Guid.NewGuid(),
                CapturedAtUtc = DateTime.UtcNow,
                Protocol = packet.Protocol,
                SourceAddress = packet.SourceAddress,
                SourcePort = packet.SourcePort,
                DestinationAddress = packet.DestinationAddress,
                DestinationPort = packet.DestinationPort,
                PacketLength = packet.Length,
                IsBlocklisted = isBlocklisted,
                BlocklistReason = sourceReason ?? destinationReason
            });

            packetsCaptured++;
        }

        if (events.Count > 0)
        {
            await connectionEventRepository.AddRangeAsync(events, cancellationToken);
        }

        return new StartNetworkCaptureResult(packetsCaptured, blocklistedCount, DateTime.UtcNow - startedAt);
    }
}
