using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Reputation;

public sealed class IpDomainReputationScoringService(
    IServiceScopeFactory scopeFactory,
    IBlocklistProvider ipBlocklistProvider,
    IDomainBlocklist domainBlocklist,
    IGeoIpBlockingService geoIp) : IIpDomainReputationScoringService
{
    public async Task<ReputationScoreResult> ScoreIpAsync(string ipAddress, CancellationToken ct = default)
    {
        int score = 0;
        var sources = new List<string>();

        if (ipBlocklistProvider.TryGetBlockReason(ipAddress, out var reason))
        {
            score += 40;
            sources.Add($"StaticBlocklist:{reason}");
        }

        if (geoIp.IsBlockedCountry(ipAddress, out var country) && country is not null)
        {
            score += 20;
            sources.Add($"GeoIP:{country}");
        }

        await AppendCustomIocMatchesAsync(ipAddress, sources, ct).ConfigureAwait(false);
        var iocScore = sources.Count(s => s.StartsWith("CustomIoc")) * 30;
        return new ReputationScoreResult(ipAddress, Math.Min(score + iocScore, 100), sources);
    }

    public async Task<ReputationScoreResult> ScoreDomainAsync(string domain, CancellationToken ct = default)
    {
        int score = 0;
        var sources = new List<string>();

        if (domainBlocklist.IsSuspiciousDomain(domain, out var reason))
        {
            score += 40;
            sources.Add($"StaticBlocklist:{reason}");
        }

        await AppendCustomIocMatchesAsync(domain, sources, ct).ConfigureAwait(false);

        var iocScore = sources.Count(s => s.StartsWith("CustomIoc")) * 30;
        return new ReputationScoreResult(domain, Math.Min(score + iocScore, 100), sources);
    }

    private async Task AppendCustomIocMatchesAsync(string value, List<string> sources, CancellationToken ct)
    {
        using var scope = scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ICustomIocRepository>();
        var matches = await repository.FindActiveByValueAsync(value, ct).ConfigureAwait(false);

        foreach (var match in matches)
        {
            sources.Add($"CustomIoc:{match.IocType}:{match.Description}");
        }
    }
}
