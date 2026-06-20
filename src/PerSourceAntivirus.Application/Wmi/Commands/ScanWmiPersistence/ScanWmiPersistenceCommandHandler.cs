using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Wmi.Commands.ScanWmiPersistence;

public class ScanWmiPersistenceCommandHandler(
    IWmiPersistenceScanner scanner,
    IWmiPersistenceAlertRepository repository)
    : IRequestHandler<ScanWmiPersistenceCommand, IReadOnlyList<WmiPersistenceAlert>>
{
    public async Task<IReadOnlyList<WmiPersistenceAlert>> Handle(
        ScanWmiPersistenceCommand request, CancellationToken cancellationToken)
    {
        var alerts = await scanner.ScanAsync(cancellationToken);

        if (alerts.Count > 0)
            await repository.AddRangeAsync(alerts, cancellationToken);

        return alerts;
    }
}
