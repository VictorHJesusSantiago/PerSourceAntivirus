using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Queries.ListCaptureDevices;

public record ListCaptureDevicesQuery : IRequest<IReadOnlyList<CaptureDeviceInfo>>;
