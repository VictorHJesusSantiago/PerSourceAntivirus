using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Network;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

// Downloads the URLhaus text blocklist, extracts hostnames from URLs, and rewrites
// domain-blocklist.txt, then reloads StaticDomainBlocklist in-process.
public sealed class UrlhausUpdater : IThreatFeedUpdater, IDisposable
{
    public string FeedName => "URLhaus";

    private const string FeedUrl = "https://urlhaus.abuse.ch/downloads/text/";

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly StaticDomainBlocklist _domainBlocklist;
    private readonly string _domainFile;

    public UrlhausUpdater(StaticDomainBlocklist domainBlocklist, string domainFile, HttpClient? http = null)
    {
        _domainBlocklist = domainBlocklist;
        _domainFile      = domainFile;
        _ownsHttp        = http is null;
        _http            = http ?? new HttpClient();
    }

    public async Task<ThreatFeedUpdateResult> UpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var text    = await _http.GetStringAsync(FeedUrl, cancellationToken);
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

    public void Dispose() { if (_ownsHttp) _http.Dispose(); }
}
