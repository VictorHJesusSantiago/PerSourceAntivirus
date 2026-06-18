using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Commands.AddWfpBlock;

public class AddWfpBlockCommandHandler(IWfpBlocker wfp, IWfpBlockRepository repo)
    : IRequestHandler<AddWfpBlockCommand, WfpBlockResult>
{
    public async Task<WfpBlockResult> Handle(AddWfpBlockCommand request, CancellationToken cancellationToken)
    {
        var result = await wfp.AddBlockAsync(request.IpAddress, request.Reason, cancellationToken);
        if (result.Success)
        {
            await repo.AddAsync(new WfpBlock
            {
                IpAddress = request.IpAddress,
                FilterIdOutboundV4 = result.FilterIdOutboundV4,
                FilterIdInboundV4 = result.FilterIdInboundV4,
                Reason = request.Reason
            }, cancellationToken);
        }
        return result;
    }
}
