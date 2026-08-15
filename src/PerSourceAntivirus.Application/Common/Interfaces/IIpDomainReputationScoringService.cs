namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IIpDomainReputationScoringService
{
    Task<ReputationScoreResult> ScoreIpAsync(string ipAddress, CancellationToken ct = default);
    Task<ReputationScoreResult> ScoreDomainAsync(string domain, CancellationToken ct = default);
}

public record ReputationScoreResult(string Value, int Score, IReadOnlyList<string> MatchedSources);
