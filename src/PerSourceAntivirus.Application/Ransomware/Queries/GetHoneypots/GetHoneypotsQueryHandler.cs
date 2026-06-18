using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Ransomware.Queries.GetHoneypots;

public class GetHoneypotsQueryHandler(IHoneypotRepository repo)
    : IRequestHandler<GetHoneypotsQuery, IReadOnlyList<HoneypotFile>>
{
    public Task<IReadOnlyList<HoneypotFile>> Handle(GetHoneypotsQuery request, CancellationToken cancellationToken)
        => repo.GetAllAsync(cancellationToken);
}
