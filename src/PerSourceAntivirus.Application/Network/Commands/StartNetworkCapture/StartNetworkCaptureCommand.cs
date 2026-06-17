using MediatR;

namespace PerSourceAntivirus.Application.Network.Commands.StartNetworkCapture;

public record StartNetworkCaptureCommand(string? DeviceName, int DurationSeconds) : IRequest<StartNetworkCaptureResult>;
