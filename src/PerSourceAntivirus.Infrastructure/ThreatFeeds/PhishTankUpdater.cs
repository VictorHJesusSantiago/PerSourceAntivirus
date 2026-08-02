using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

// PhishTank — bulk CSV of verified-online phishing URLs; extracts the registered domain from
// each URL and feeds the domain blocklist (used for both file/script analysis and DNS/hosts
// filtering) plus records the raw URL as a CustomIoc for hunting.
public sealed class PhishTankUpdater : IThreatFeedUpdater
{
    public string FeedName => "PhishTank";

    private const string FeedUrl = "http://data.phishtank.com/data/online-valid.csv";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IDomainBlocklist _domainBlocklist;
    private readonly string _domainBlocklistFile;
    private readonly FeedContentCache _cache;

    public PhishTankUpdater(
        IServiceScopeFactory scopeFactory,
        IDomainBlocklist domainBlocklist,
        string domainBlocklistFile,
        string cacheStateFile,
        IHttpClientFactory httpClientFactory)
    {
        _scopeFactory = scopeFactory;
        _domainBlocklist = domainBlocklist;
        _domainBlocklistFile = domainBlocklistFile;
        _cache = new FeedContentCache(cacheStateFile);
        _httpClientFactory = httpClientFactory;
    }

    public async Task<ThreatFeedUpdateResult> UpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var http = _httpClientFactory.CreateClient(ThreatFeedHttpClient.Name);
            var csv = await http.GetStringAsync(FeedUrl, cancellationToken).ConfigureAwait(false);

            if (!_cache.HasChangedAndRecord(FeedName, csv))
                return new ThreatFeedUpdateResult(FeedName, 0, 0, true, "No change since last update");

            var urls = ParseUrls(csv);
            var domains = urls
                .Select(ExtractDomain)
                .Where(d => d is not null)
                .Select(d => d!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (domains.Count == 0)
                return new ThreatFeedUpdateResult(FeedName, 0, 0, true);

            using (var scope = _scopeFactory.CreateScope())
            {
                var repository = scope.ServiceProvider.GetRequiredService<ICustomIocRepository>();
                var existing = (await repository.GetByTypeAsync("PhishTank", cancellationToken).ConfigureAwait(false))
                    .Select(i => i.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

                var newDomains = new List<string>();
                foreach (var domain in domains)
                {
                    if (existing.Contains(domain)) continue;
                    newDomains.Add(domain);

                    await repository.AddAsync(new CustomIoc
                    {
                        Id = Guid.NewGuid(),
                        IocType = "PhishTank",
                        Value = domain,
                        Description = "Phishing domain",
                        Tags = "phishing",
                        IsActive = true,
                        CreatedAtUtc = DateTime.UtcNow
                    }, cancellationToken).ConfigureAwait(false);
                }

                if (newDomains.Count > 0)
                {
                    await File.AppendAllLinesAsync(_domainBlocklistFile, newDomains, cancellationToken).ConfigureAwait(false);
                    _domainBlocklist.Reload();
                }
            }

            return new ThreatFeedUpdateResult(FeedName, domains.Count, domains.Count, true);
        }
        catch (Exception ex)
        {
            return new ThreatFeedUpdateResult(FeedName, 0, 0, false, ex.Message);
        }
    }

    // CSV columns: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
    internal static List<string> ParseUrls(string csv)
    {
        var urls = new List<string>();
        var lines = csv.Split('\n');
        for (int i = 1; i < lines.Length; i++) // skip header
        {
            var line = lines[i].Trim();
            if (line.Length == 0) continue;
            var fields = SplitCsvLine(line);
            if (fields.Count >= 2 && fields[1].Length > 0) urls.Add(fields[1]);
        }
        return urls;
    }

    internal static string? ExtractDomain(string url)
    {
        try
        {
            var uri = new Uri(url, UriKind.Absolute);
            return uri.Host.ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static List<string> SplitCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;

        foreach (var c in line)
        {
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (c == ',' && !inQuotes) { fields.Add(current.ToString()); current.Clear(); continue; }
            current.Append(c);
        }
        fields.Add(current.ToString());
        return fields;
    }


}
