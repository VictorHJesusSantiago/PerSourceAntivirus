using MediatR;
using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Rootkit.Queries.GetRootkitFindings;
public record GetRootkitFindingsQuery : IRequest<IReadOnlyList<RootkitFinding>>;
