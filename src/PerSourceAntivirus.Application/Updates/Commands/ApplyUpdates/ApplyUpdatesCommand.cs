using MediatR;

namespace PerSourceAntivirus.Application.Updates.Commands.ApplyUpdates;

public record ApplyUpdatesCommand : IRequest<int>;
