using MediatR;

namespace PerSourceAntivirus.Application.Network.Commands.RemoveWfpBlock;

public record RemoveWfpBlockCommand(string IpAddress) : IRequest<bool>;
