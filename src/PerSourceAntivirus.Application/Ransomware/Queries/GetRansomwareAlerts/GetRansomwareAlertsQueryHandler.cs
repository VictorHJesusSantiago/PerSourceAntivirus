using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Ransomware.Queries.GetRansomwareAlerts;

public class GetRansomwareAlertsQueryHandler(IRansomwareAlertRepository repo)
    : IRequestHandler<GetRansomwareAlertsQuery, IReadOnlyList<RansomwareAlert>>
{
    public Task<IReadOnlyList<RansomwareAlert>> Handle(GetRansomwareAlertsQuery request, CancellationToken cancellationToken)
        => repo.GetAllAsync(request.OnlyCritical, cancellationToken);
}
