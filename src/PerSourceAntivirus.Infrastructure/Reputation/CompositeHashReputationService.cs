using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Reputation;

public class CompositeHashReputationService(
    LocalHashReputationService local,
    VirusTotalHashReputationService virusTotal) : IHashReputationService
{
    public async Task<HashReputationData?> CheckAsync(string sha256, CancellationToken cancellationToken = default)
    {
        // Local list is checked first: instant, no quota cost.
        var localResult = await local.CheckAsync(sha256, cancellationToken);
        if (localResult is not null) return localResult;

        // Fall through to VirusTotal if configured.
        return await virusTotal.CheckAsync(sha256, cancellationToken);
    }
}
