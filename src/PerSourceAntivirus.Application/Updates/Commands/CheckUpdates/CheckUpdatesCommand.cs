using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Updates.Commands.CheckUpdates;

public record CheckUpdatesCommand : IRequest<UpdateCheckResult>;
