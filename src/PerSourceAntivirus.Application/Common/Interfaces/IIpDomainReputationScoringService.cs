namespace PerSourceAntivirus.Application.Common.Interfaces;

// Aggregates every locally-available IP/domain source (static blocklists, GeoIP,
// OTX/ThreatFox/PhishTank-sourced CustomIocs) into a single 0-100 risk score instead of
// forcing callers to consult each feed individually.
public interface IIpDomainReputationScoringService
{
    Task<ReputationScoreResult> ScoreIpAsync(string ipAddress, CancellationToken ct = default);
    Task<ReputationScoreResult> ScoreDomainAsync(string domain, CancellationToken ct = default);
}

public record ReputationScoreResult(string Value, int Score, IReadOnlyList<string> MatchedSources);
