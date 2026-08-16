using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Reputation;

public class CompositeHashReputationService(
    LocalHashReputationService local,
    VirusTotalHashReputationService virusTotal) : IHashReputationService
{
    public async Task<HashReputationData?> CheckAsync(string sha256, CancellationToken cancellationToken = default)
    {
        var localResult = await local.CheckAsync(sha256, cancellationToken);
        if (localResult is not null) return localResult;

        return await virusTotal.CheckAsync(sha256, cancellationToken);
    }
}
