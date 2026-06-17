using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Scans.Queries.GetScheduledScans;

public record GetScheduledScansQuery() : IRequest<IReadOnlyList<ScheduledScan>>;
