using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Queries.GetWfpBlocks;

public class GetWfpBlocksQueryHandler(IWfpBlocker wfp)
    : IRequestHandler<GetWfpBlocksQuery, IReadOnlyList<WfpBlockEntry>>
{
    public Task<IReadOnlyList<WfpBlockEntry>> Handle(GetWfpBlocksQuery request, CancellationToken cancellationToken)
        => wfp.GetActiveBlocksAsync(cancellationToken);
}
