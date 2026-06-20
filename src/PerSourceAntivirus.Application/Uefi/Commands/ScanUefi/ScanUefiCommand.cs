using MediatR;
using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Uefi.Commands.ScanUefi;
public record ScanUefiCommand : IRequest<IReadOnlyList<UefiFinding>>;
