using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Queries.GetNetworkConnectionEvents;

public record GetNetworkConnectionEventsQuery(bool OnlyBlocklisted) : IRequest<IReadOnlyList<NetworkConnectionEvent>>;
