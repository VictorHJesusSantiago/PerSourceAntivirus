using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Wmi.Queries.GetWmiAlerts;

public class GetWmiAlertsQueryHandler(IWmiPersistenceAlertRepository repository)
    : IRequestHandler<GetWmiAlertsQuery, IReadOnlyList<WmiPersistenceAlert>>
{
    public async Task<IReadOnlyList<WmiPersistenceAlert>> Handle(
        GetWmiAlertsQuery request, CancellationToken cancellationToken)
    {
        return await repository.GetAllAsync(cancellationToken);
    }
}
