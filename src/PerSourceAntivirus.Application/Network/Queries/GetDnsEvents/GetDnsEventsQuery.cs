using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Queries.GetDnsEvents;

public record GetDnsEventsQuery(bool OnlySuspicious = false) : IRequest<IReadOnlyList<DnsQueryEvent>>;
