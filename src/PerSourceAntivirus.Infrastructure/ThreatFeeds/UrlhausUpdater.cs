using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Network;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

// Downloads the URLhaus text blocklist, extracts hostnames from URLs, and rewrites
// domain-blocklist.txt, then reloads StaticDomainBlocklist in-process.
public sealed class UrlhausUpdater : IThreatFeedUpdater
{
    public string FeedName => "URLhaus";

    private const string FeedUrl = "https://urlhaus.abuse.ch/downloads/text/";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly StaticDomainBlocklist _domainBlocklist;
    private readonly string _domainFile;

    public UrlhausUpdater(StaticDomainBlocklist domainBlocklist, string domainFile, IHttpClientFactory httpClientFactory)
    {
        _domainBlocklist   = domainBlocklist;
        _domainFile        = domainFile;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<ThreatFeedUpdateResult> UpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var http = _httpClientFactory.CreateClient(ThreatFeedHttpClient.Name);
            var text    = await http.GetStringAsync(FeedUrl, cancellationToken);
            var domains = ParseDomains(text);
            await File.WriteAllLinesAsync(_domainFile, domains, cancellationToken);
            _domainBlocklist.Reload();
            return new ThreatFeedUpdateResult(FeedName, domains.Count, domains.Count, true);
        }
        catch (Exception ex)
        {
            return new ThreatFeedUpdateResult(FeedName, 0, 0, false, ex.Message);
        }
    }

    // Extracts unique lowercase hostnames from URL lines.
    internal static List<string> ParseDomains(string text)
    {
        var seen    = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var domains = new List<string>();

        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;

            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
            {
                var host = uri.Host.ToLowerInvariant();
                if (host.Length > 0 && seen.Add(host))
                    domains.Add(host);
            }
        }

        return domains;
    }
}
