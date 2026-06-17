using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Queries.ListCaptureDevices;

public class ListCaptureDevicesQueryHandler(INetworkMonitor networkMonitor)
    : IRequestHandler<ListCaptureDevicesQuery, IReadOnlyList<CaptureDeviceInfo>>
{
    public Task<IReadOnlyList<CaptureDeviceInfo>> Handle(ListCaptureDevicesQuery request, CancellationToken cancellationToken)
        => Task.FromResult(networkMonitor.GetAvailableDevices());
}
