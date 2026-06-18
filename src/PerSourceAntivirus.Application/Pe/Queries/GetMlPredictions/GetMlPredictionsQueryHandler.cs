using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Pe.Queries.GetMlPredictions;

public class GetMlPredictionsQueryHandler(IPeMlPredictionRepository repo)
    : IRequestHandler<GetMlPredictionsQuery, IReadOnlyList<PeMlPrediction>>
{
    public Task<IReadOnlyList<PeMlPrediction>> Handle(GetMlPredictionsQuery request, CancellationToken cancellationToken)
        => repo.GetAllAsync(request.ClassificationFilter, cancellationToken);
}
