using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Scans.Commands.AddScheduledScan;

public class AddScheduledScanCommandHandler(IScheduledScanRepository repository)
    : IRequestHandler<AddScheduledScanCommand, AddScheduledScanResult>
{
    public async Task<AddScheduledScanResult> Handle(AddScheduledScanCommand request, CancellationToken cancellationToken)
    {
        var scan = new ScheduledScan
        {
            Id = Guid.NewGuid(),
            Path = request.Path,
            IntervalMinutes = request.IntervalMinutes,
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow
        };

        await repository.AddAsync(scan, cancellationToken);
        return new AddScheduledScanResult(scan.Id, scan.Path, scan.IntervalMinutes);
    }
}
