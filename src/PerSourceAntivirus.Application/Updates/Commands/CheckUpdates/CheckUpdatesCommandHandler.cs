using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Updates.Commands.CheckUpdates;

public class CheckUpdatesCommandHandler(IAutoUpdater autoUpdater)
    : IRequestHandler<CheckUpdatesCommand, UpdateCheckResult>
{
    public async Task<UpdateCheckResult> Handle(CheckUpdatesCommand request, CancellationToken cancellationToken)
    {
        return await autoUpdater.CheckForUpdatesAsync(cancellationToken);
    }
}
