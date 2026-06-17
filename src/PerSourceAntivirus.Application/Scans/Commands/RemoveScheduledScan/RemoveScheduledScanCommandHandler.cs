using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Scans.Commands.RemoveScheduledScan;

public class RemoveScheduledScanCommandHandler(IScheduledScanRepository repository)
    : IRequestHandler<RemoveScheduledScanCommand, Unit>
{
    public async Task<Unit> Handle(RemoveScheduledScanCommand request, CancellationToken cancellationToken)
    {
        await repository.RemoveAsync(request.Id, cancellationToken);
        return Unit.Value;
    }
}
