using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Fileless.Queries.GetFilelessAlerts;

public class GetFilelessAlertsQueryHandler(IFilelessAlertRepository repository)
    : IRequestHandler<GetFilelessAlertsQuery, IReadOnlyList<FilelessAlert>>
{
    public Task<IReadOnlyList<FilelessAlert>> Handle(GetFilelessAlertsQuery request, CancellationToken cancellationToken)
        => repository.GetAllAsync(cancellationToken);
}
