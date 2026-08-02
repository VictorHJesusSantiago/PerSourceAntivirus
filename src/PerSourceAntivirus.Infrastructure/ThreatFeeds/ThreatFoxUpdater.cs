using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

// Abuse.ch ThreatFox — pulls recent IOCs (IP:port, domain, URL, hash) via the public JSON API
// and both (a) records them as CustomIoc entries for hunting/triage and (b) feeds IP/domain
// blocklists so they are enforced immediately.
public sealed class ThreatFoxUpdater : IThreatFeedUpdater
{
    public string FeedName => "ThreatFox";

    private const string ApiUrl = "https://threatfox-api.abuse.ch/api/v1/";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IBlocklistProvider _ipBlocklistProvider;
    private readonly string _ipBlocklistFile;
    private readonly IDomainBlocklist _domainBlocklist;
    private readonly string _domainBlocklistFile;
    private readonly FeedContentCache _cache;

    public ThreatFoxUpdater(
        IServiceScopeFactory scopeFactory,
        IBlocklistProvider ipBlocklistProvider,
        string ipBlocklistFile,
        IDomainBlocklist domainBlocklist,
        string domainBlocklistFile,
        string cacheStateFile,
        IHttpClientFactory httpClientFactory)
    {
        _scopeFactory = scopeFactory;
        _ipBlocklistProvider = ipBlocklistProvider;
        _ipBlocklistFile = ipBlocklistFile;
        _domainBlocklist = domainBlocklist;
        _domainBlocklistFile = domainBlocklistFile;
        _cache = new FeedContentCache(cacheStateFile);
        _httpClientFactory = httpClientFactory;
    }

    public async Task<ThreatFeedUpdateResult> UpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var requestBody = new StringContent(
                JsonSerializer.Serialize(new { query = "get_iocs", days = 1 }),
                Encoding.UTF8, "application/json");

            using var http = _httpClientFactory.CreateClient(ThreatFeedHttpClient.Name);
            using var response = await http.PostAsync(ApiUrl, requestBody, cancellationToken).ConfigureAwait(false);
            var raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!_cache.HasChangedAndRecord(FeedName, raw))
                return new ThreatFeedUpdateResult(FeedName, 0, 0, true, "No change since last update");

            var iocs = ParseIocs(raw);
            if (iocs.Count == 0)
                return new ThreatFeedUpdateResult(FeedName, 0, 0, true);

            var newIps = new List<string>();
            var newDomains = new List<string>();

            using (var scope = _scopeFactory.CreateScope())
            {
                var repository = scope.ServiceProvider.GetRequiredService<ICustomIocRepository>();
                var existingByValue = (await repository.GetByTypeAsync("ThreatFox", cancellationToken).ConfigureAwait(false))
                    .Select(i => i.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var ioc in iocs)
                {
                    if (existingByValue.Contains(ioc.value)) continue;

                    await repository.AddAsync(new CustomIoc
                    {
                        Id = Guid.NewGuid(),
                        IocType = "ThreatFox",
                        Value = ioc.value,
                        Description = ioc.threatType,
                        Tags = ioc.malware,
                        IsActive = true,
                        CreatedAtUtc = DateTime.UtcNow
                    }, cancellationToken).ConfigureAwait(false);

                    if (ioc.type == "ip") newIps.Add(ioc.value);
                    else if (ioc.type == "domain") newDomains.Add(ioc.value);
                }
            }

            if (newIps.Count > 0)
            {
                await File.AppendAllLinesAsync(_ipBlocklistFile, newIps, cancellationToken).ConfigureAwait(false);
                _ipBlocklistProvider.Reload();
            }
            if (newDomains.Count > 0)
            {
                await File.AppendAllLinesAsync(_domainBlocklistFile, newDomains, cancellationToken).ConfigureAwait(false);
                _domainBlocklist.Reload();
            }

            return new ThreatFeedUpdateResult(FeedName, iocs.Count, iocs.Count, true);
        }
        catch (Exception ex)
        {
            return new ThreatFeedUpdateResult(FeedName, 0, 0, false, ex.Message);
        }
    }

    internal static List<(string type, string value, string threatType, string malware)> ParseIocs(string json)
    {
        var result = new List<(string, string, string, string)>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                return result;

            foreach (var item in data.EnumerateArray())
            {
                var iocValue = item.TryGetProperty("ioc", out var iocEl) ? iocEl.GetString() ?? "" : "";
                var iocType = item.TryGetProperty("ioc_type", out var typeEl) ? typeEl.GetString() ?? "" : "";
                var threatType = item.TryGetProperty("threat_type", out var ttEl) ? ttEl.GetString() ?? "" : "";
                var malware = item.TryGetProperty("malware_printable", out var mEl) ? mEl.GetString() ?? "" : "";

                if (iocValue.Length == 0) continue;

                string normalizedType = iocType switch
                {
                    "ip:port" => "ip",
                    "domain" => "domain",
                    _ => iocType
                };
                string normalizedValue = normalizedType == "ip" && iocValue.Contains(':')
                    ? iocValue[..iocValue.IndexOf(':')]
                    : iocValue;

                result.Add((normalizedType, normalizedValue, threatType, malware));
            }
        }
        catch { }
        return result;
    }


}
