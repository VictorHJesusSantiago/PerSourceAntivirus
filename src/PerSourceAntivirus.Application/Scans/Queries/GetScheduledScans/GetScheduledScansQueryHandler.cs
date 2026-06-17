using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Scans.Queries.GetScheduledScans;

public class GetScheduledScansQueryHandler(IScheduledScanRepository repository)
    : IRequestHandler<GetScheduledScansQuery, IReadOnlyList<ScheduledScan>>
{
    public Task<IReadOnlyList<ScheduledScan>> Handle(GetScheduledScansQuery request, CancellationToken cancellationToken)
        => repository.GetAllAsync(cancellationToken);
}
