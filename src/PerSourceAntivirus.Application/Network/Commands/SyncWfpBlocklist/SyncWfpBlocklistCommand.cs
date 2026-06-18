using MediatR;

namespace PerSourceAntivirus.Application.Network.Commands.SyncWfpBlocklist;

public record SyncWfpBlocklistCommand : IRequest<SyncWfpBlocklistResult>;

public record SyncWfpBlocklistResult(int Added, int AlreadyBlocked, int Errors);
