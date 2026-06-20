using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Wmi.Queries.GetWmiAlerts;

public record GetWmiAlertsQuery : IRequest<IReadOnlyList<WmiPersistenceAlert>>;
