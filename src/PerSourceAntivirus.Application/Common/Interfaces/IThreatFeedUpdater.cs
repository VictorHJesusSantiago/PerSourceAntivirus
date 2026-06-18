namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IThreatFeedUpdater
{
    string FeedName { get; }
    Task<ThreatFeedUpdateResult> UpdateAsync(CancellationToken cancellationToken = default);
}

public record ThreatFeedUpdateResult(
    string FeedName,
    int RecordsAdded,
    int RecordsTotal,
    bool Success,
    string? ErrorMessage = null);
