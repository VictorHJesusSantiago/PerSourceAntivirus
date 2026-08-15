using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Commands.SyncWfpBlocklist;

public class SyncWfpBlocklistCommandHandler(IWfpBlocker wfp, IBlocklistProvider blocklist, IWfpBlockRepository repo)
    : IRequestHandler<SyncWfpBlocklistCommand, SyncWfpBlocklistResult>
{
    public async Task<SyncWfpBlocklistResult> Handle(SyncWfpBlocklistCommand request, CancellationToken cancellationToken)
    {
        var alreadyInWfp = new HashSet<string>(
            (await wfp.GetActiveBlocksAsync(cancellationToken)).Select(b => b.IpAddress),
            StringComparer.OrdinalIgnoreCase);

        var desired = new HashSet<string>(blocklist.GetAllBlockedAddresses(), StringComparer.OrdinalIgnoreCase);
        desired.UnionWith(await repo.GetActiveIpsAsync(cancellationToken));

        var missing = desired.Where(ip => !alreadyInWfp.Contains(ip)).ToList();
        var added = await wfp.SyncFromIpListAsync(missing, cancellationToken);

        return new SyncWfpBlocklistResult(
            Added: added,
            AlreadyBlocked: alreadyInWfp.Count,
            Errors: missing.Count - added);
    }
}
