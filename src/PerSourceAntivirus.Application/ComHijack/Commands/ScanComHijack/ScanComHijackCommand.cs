using MediatR;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.ComHijack.Commands.ScanComHijack;

public record ScanComHijackCommand : IRequest<IReadOnlyList<ComHijackAlert>>;
