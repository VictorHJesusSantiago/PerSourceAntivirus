using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.ComHijack.Queries.GetComAlerts;

public class GetComAlertsQueryHandler(IComHijackAlertRepository repo)
    : IRequestHandler<GetComAlertsQuery, IReadOnlyList<ComHijackAlert>>
{
    public Task<IReadOnlyList<ComHijackAlert>> Handle(GetComAlertsQuery request, CancellationToken cancellationToken)
        => repo.GetAllAsync(cancellationToken);
}
