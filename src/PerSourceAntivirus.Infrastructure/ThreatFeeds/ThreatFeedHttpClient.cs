namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

// Named IHttpClientFactory client shared by every threat-feed updater. Centralising the name
// keeps the timeout/User-Agent policy in one place (configured in DependencyInjection) instead of
// each updater inventing its own.
internal static class ThreatFeedHttpClient
{
    public const string Name = "psav-threat-feeds";
}
