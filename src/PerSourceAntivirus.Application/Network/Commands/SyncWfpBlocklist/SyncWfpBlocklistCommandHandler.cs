using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Commands.SyncWfpBlocklist;

public class SyncWfpBlocklistCommandHandler(IWfpBlocker wfp, IBlocklistProvider blocklist, IWfpBlockRepository repo)
    : IRequestHandler<SyncWfpBlocklistCommand, SyncWfpBlocklistResult>
{
    public async Task<SyncWfpBlocklistResult> Handle(SyncWfpBlocklistCommand request, CancellationToken cancellationToken)
    {
        var existingBlocks = await repo.GetActiveIpsAsync(cancellationToken);
        var existing = new HashSet<string>(existingBlocks, StringComparer.OrdinalIgnoreCase);

        var allIps = await wfp.GetActiveBlocksAsync(cancellationToken);
        var wfpActive = new HashSet<string>(allIps.Select(b => b.IpAddress), StringComparer.OrdinalIgnoreCase);

        // Sync blocklist IPs into WFP — the blocklist provider has the known-malicious IPs
        var added = 0;
        var alreadyBlocked = 0;
        var errors = 0;

        var toBlock = await wfp.SyncFromIpListAsync(
            existing.Where(ip => !wfpActive.Contains(ip)),
            cancellationToken);

        added = toBlock;
        alreadyBlocked = wfpActive.Count;

        return new SyncWfpBlocklistResult(added, alreadyBlocked, errors);
    }
}
