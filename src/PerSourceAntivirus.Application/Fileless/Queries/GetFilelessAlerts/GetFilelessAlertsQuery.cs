using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Fileless.Queries.GetFilelessAlerts;

public record GetFilelessAlertsQuery : IRequest<IReadOnlyList<FilelessAlert>>;
