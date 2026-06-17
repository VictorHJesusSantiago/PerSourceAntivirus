using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Queries.GetNetworkConnectionEvents;

public class GetNetworkConnectionEventsQueryHandler(INetworkConnectionEventRepository repository)
    : IRequestHandler<GetNetworkConnectionEventsQuery, IReadOnlyList<NetworkConnectionEvent>>
{
    public Task<IReadOnlyList<NetworkConnectionEvent>> Handle(GetNetworkConnectionEventsQuery request, CancellationToken cancellationToken)
        => repository.GetAllAsync(request.OnlyBlocklisted, cancellationToken);
}
