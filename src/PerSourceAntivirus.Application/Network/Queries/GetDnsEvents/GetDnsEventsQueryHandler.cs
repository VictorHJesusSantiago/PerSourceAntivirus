using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Queries.GetDnsEvents;

public class GetDnsEventsQueryHandler(IDnsEventRepository repository)
    : IRequestHandler<GetDnsEventsQuery, IReadOnlyList<DnsQueryEvent>>
{
    public Task<IReadOnlyList<DnsQueryEvent>> Handle(GetDnsEventsQuery request, CancellationToken cancellationToken)
        => repository.GetAllAsync(request.OnlySuspicious, cancellationToken);
}
