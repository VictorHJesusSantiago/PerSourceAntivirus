using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Updates.Commands.ApplyUpdates;

public class ApplyUpdatesCommandHandler(IAutoUpdater autoUpdater)
    : IRequestHandler<ApplyUpdatesCommand, int>
{
    public async Task<int> Handle(ApplyUpdatesCommand request, CancellationToken cancellationToken)
    {
        return await autoUpdater.ApplyUpdatesAsync(cancellationToken);
    }
}
