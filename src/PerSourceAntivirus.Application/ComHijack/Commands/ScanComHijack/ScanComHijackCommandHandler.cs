using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.ComHijack.Commands.ScanComHijack;

public class ScanComHijackCommandHandler(IComHijackMonitor monitor, IComHijackAlertRepository repo)
    : IRequestHandler<ScanComHijackCommand, IReadOnlyList<ComHijackAlert>>
{
    public async Task<IReadOnlyList<ComHijackAlert>> Handle(ScanComHijackCommand request, CancellationToken cancellationToken)
    {
        var alerts = await monitor.ScanCurrentStateAsync(cancellationToken);
        foreach (var alert in alerts)
            await repo.AddAsync(alert, cancellationToken);
        return alerts;
    }
}
