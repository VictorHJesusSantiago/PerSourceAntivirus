using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Process.Queries.GetProcessEvents;

public record GetProcessEventsQuery(bool OnlySuspicious = false) : IRequest<IReadOnlyList<ProcessEvent>>;
