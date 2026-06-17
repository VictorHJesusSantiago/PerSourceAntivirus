using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Process.Queries.GetProcessEvents;

public class GetProcessEventsQueryHandler(IProcessEventRepository repository)
    : IRequestHandler<GetProcessEventsQuery, IReadOnlyList<ProcessEvent>>
{
    public Task<IReadOnlyList<ProcessEvent>> Handle(GetProcessEventsQuery request, CancellationToken cancellationToken)
        => repository.GetAllAsync(request.OnlySuspicious, cancellationToken);
}
