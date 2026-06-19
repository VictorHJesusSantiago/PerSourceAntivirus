using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
namespace PerSourceAntivirus.Application.Rootkit.Commands.ScanRootkits;
public class ScanRootkitsCommandHandler(IRootkitScanner scanner, IRootkitFindingRepository repo)
    : IRequestHandler<ScanRootkitsCommand, IReadOnlyList<RootkitFinding>>
{
    public async Task<IReadOnlyList<RootkitFinding>> Handle(ScanRootkitsCommand request, CancellationToken cancellationToken)
    {
        var findings = await scanner.ScanAsync(cancellationToken);
        if (findings.Count > 0)
            await repo.AddRangeAsync(findings, cancellationToken);
        return findings;
    }
}
