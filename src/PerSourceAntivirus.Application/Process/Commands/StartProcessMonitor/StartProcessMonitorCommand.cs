using MediatR;

namespace PerSourceAntivirus.Application.Process.Commands.StartProcessMonitor;

public record StartProcessMonitorCommand(int DurationSeconds) : IRequest<StartProcessMonitorResult>;
