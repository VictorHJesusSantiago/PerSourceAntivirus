using MediatR;

namespace PerSourceAntivirus.Application.Network.Commands.StartDnsMonitor;

public record StartDnsMonitorCommand(string? DeviceName, int DurationSeconds) : IRequest<StartDnsMonitorResult>;
