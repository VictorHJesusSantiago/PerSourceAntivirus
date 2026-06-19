using MediatR;
using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Rootkit.Commands.ScanRootkits;
public record ScanRootkitsCommand : IRequest<IReadOnlyList<RootkitFinding>>;
