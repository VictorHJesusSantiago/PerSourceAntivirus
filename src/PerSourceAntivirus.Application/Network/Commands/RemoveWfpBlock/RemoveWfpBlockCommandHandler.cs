using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Commands.RemoveWfpBlock;

public class RemoveWfpBlockCommandHandler(IWfpBlocker wfp, IWfpBlockRepository repo)
    : IRequestHandler<RemoveWfpBlockCommand, bool>
{
    public async Task<bool> Handle(RemoveWfpBlockCommand request, CancellationToken cancellationToken)
    {
        var removed = await wfp.RemoveBlockAsync(request.IpAddress, cancellationToken);
        if (removed)
            await repo.DeactivateAsync(request.IpAddress, cancellationToken);
        return removed;
    }
}
