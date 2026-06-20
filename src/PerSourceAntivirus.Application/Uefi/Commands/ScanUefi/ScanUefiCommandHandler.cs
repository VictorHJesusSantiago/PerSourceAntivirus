using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Uefi.Commands.ScanUefi;
public class ScanUefiCommandHandler(IUefiScanner scanner, IUefiFindingRepository repository)
    : IRequestHandler<ScanUefiCommand, IReadOnlyList<UefiFinding>>
{
    public async Task<IReadOnlyList<UefiFinding>> Handle(ScanUefiCommand request, CancellationToken cancellationToken)
    {
        var findings = await scanner.ScanAsync(cancellationToken);
        if (findings.Count > 0)
            await repository.AddRangeAsync(findings, cancellationToken);
        return findings;
    }
}
