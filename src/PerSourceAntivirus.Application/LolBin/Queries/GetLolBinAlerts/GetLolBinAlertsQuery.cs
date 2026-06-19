using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.LolBin.Queries.GetLolBinAlerts;

public record GetLolBinAlertsQuery : IRequest<IReadOnlyList<LolBinAlert>>;
