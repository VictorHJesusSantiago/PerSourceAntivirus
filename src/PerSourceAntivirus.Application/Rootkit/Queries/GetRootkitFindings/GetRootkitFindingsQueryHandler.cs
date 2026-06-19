using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Rootkit.Queries.GetRootkitFindings;
public class GetRootkitFindingsQueryHandler(IRootkitFindingRepository repo)
    : IRequestHandler<GetRootkitFindingsQuery, IReadOnlyList<RootkitFinding>>
{
    public Task<IReadOnlyList<RootkitFinding>> Handle(GetRootkitFindingsQuery request, CancellationToken cancellationToken)
        => repo.GetAllAsync(cancellationToken);
}
