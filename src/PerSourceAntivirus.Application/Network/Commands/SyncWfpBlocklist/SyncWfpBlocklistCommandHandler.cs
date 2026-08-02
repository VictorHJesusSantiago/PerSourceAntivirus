using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Commands.SyncWfpBlocklist;

public class SyncWfpBlocklistCommandHandler(IWfpBlocker wfp, IBlocklistProvider blocklist, IWfpBlockRepository repo)
    : IRequestHandler<SyncWfpBlocklistCommand, SyncWfpBlocklistResult>
{
    // [AUDIT FIX — HIGH, Domain 1 Obscured Intent / correctness] This handler injected
    // IBlocklistProvider and carried a comment saying it synced "the blocklist provider ...
    // known-malicious IPs" into WFP — but it never read `blocklist` (the compiler flagged it as
    // an unread parameter, CS9113). It actually re-synced only IPs *already recorded* in the WFP
    // block repository, so every IP newly imported by the threat-feed updaters (FeodoTracker,
    // ThreatFox, OTX) into ip-blocklist.txt was never pushed into a WFP filter — the
    // "threat feed -> kernel-level enforcement" path was inert.
    //
    // IBlocklistProvider previously had no way to enumerate its entries (only a per-IP lookup),
    // which is why the parameter went unused; GetAllBlockedAddresses() was added for this.
    public async Task<SyncWfpBlocklistResult> Handle(SyncWfpBlocklistCommand request, CancellationToken cancellationToken)
    {
        var alreadyInWfp = new HashSet<string>(
            (await wfp.GetActiveBlocksAsync(cancellationToken)).Select(b => b.IpAddress),
            StringComparer.OrdinalIgnoreCase);

        // Union of both sources of truth: the on-disk blocklist (fed by the threat-feed updaters)
        // and IPs previously persisted as blocked (so blocks survive a WFP engine restart).
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
