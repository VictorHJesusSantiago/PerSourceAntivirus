using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.ComHijack.Queries.GetComAlerts;

public record GetComAlertsQuery : IRequest<IReadOnlyList<ComHijackAlert>>;
