using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.LolBin.Queries.GetLolBinAlerts;

public class GetLolBinAlertsQueryHandler(ILolBinAlertRepository repository)
    : IRequestHandler<GetLolBinAlertsQuery, IReadOnlyList<LolBinAlert>>
{
    public Task<IReadOnlyList<LolBinAlert>> Handle(GetLolBinAlertsQuery request, CancellationToken cancellationToken)
        => repository.GetAllAsync(cancellationToken);
}
