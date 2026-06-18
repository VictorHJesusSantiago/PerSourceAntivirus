using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Pe.Queries.GetMlPredictions;

public record GetMlPredictionsQuery(string? ClassificationFilter = null)
    : IRequest<IReadOnlyList<PeMlPrediction>>;
