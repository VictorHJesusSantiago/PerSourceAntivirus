using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

// AlienVault OTX — pulls indicators from the subscribed-pulses feed. Requires an API key
// (Settings > Threat Intel); with no key configured this becomes a graceful no-op, same
// convention as VirusTotalHashReputationService.
public sealed class OtxThreatFeedUpdater : IThreatFeedUpdater
{
    public string FeedName => "AlienVault OTX";

    private const string ApiUrl = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _apiKey;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IBlocklistProvider _ipBlocklistProvider;
    private readonly string _ipBlocklistFile;
    private readonly IDomainBlocklist _domainBlocklist;
    private readonly string _domainBlocklistFile;
    private readonly FeedContentCache _cache;

    public OtxThreatFeedUpdater(
        string apiKey,
        IServiceScopeFactory scopeFactory,
        IBlocklistProvider ipBlocklistProvider,
        string ipBlocklistFile,
        IDomainBlocklist domainBlocklist,
        string domainBlocklistFile,
        string cacheStateFile,
        IHttpClientFactory httpClientFactory)
    {
        _apiKey = apiKey;
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
        if (string.IsNullOrWhiteSpace(_apiKey))
            return new ThreatFeedUpdateResult(FeedName, 0, 0, true, "No API key configured — skipped");

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ApiUrl);
            request.Headers.Add("X-OTX-API-KEY", _apiKey);

            using var http = _httpClientFactory.CreateClient(ThreatFeedHttpClient.Name);
            using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return new ThreatFeedUpdateResult(FeedName, 0, 0, false, $"HTTP {(int)response.StatusCode}");

            if (!_cache.HasChangedAndRecord(FeedName, raw))
                return new ThreatFeedUpdateResult(FeedName, 0, 0, true, "No change since last update");

            var indicators = ParseIndicators(raw);
            if (indicators.Count == 0)
                return new ThreatFeedUpdateResult(FeedName, 0, 0, true);

            var newIps = new List<string>();
            var newDomains = new List<string>();

            using (var scope = _scopeFactory.CreateScope())
            {
                var repository = scope.ServiceProvider.GetRequiredService<ICustomIocRepository>();
                var existing = (await repository.GetByTypeAsync("OTX", cancellationToken).ConfigureAwait(false))
                    .Select(i => i.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var (type, value, pulseName) in indicators)
                {
                    if (existing.Contains(value)) continue;

                    await repository.AddAsync(new CustomIoc
                    {
                        Id = Guid.NewGuid(),
                        IocType = "OTX",
                        Value = value,
                        Description = pulseName,
                        Tags = type,
                        IsActive = true,
                        CreatedAtUtc = DateTime.UtcNow
                    }, cancellationToken).ConfigureAwait(false);

                    if (type is "IPv4") newIps.Add(value);
                    else if (type is "domain" or "hostname") newDomains.Add(value);
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

            return new ThreatFeedUpdateResult(FeedName, indicators.Count, indicators.Count, true);
        }
        catch (Exception ex)
        {
            return new ThreatFeedUpdateResult(FeedName, 0, 0, false, ex.Message);
        }
    }

    internal static List<(string type, string value, string pulseName)> ParseIndicators(string json)
    {
        var result = new List<(string, string, string)>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
                return result;

            foreach (var pulse in results.EnumerateArray())
            {
                var pulseName = pulse.TryGetProperty("name", out var nameEl) ? nameEl.GetString() ?? "" : "";
                if (!pulse.TryGetProperty("indicators", out var indicators) || indicators.ValueKind != JsonValueKind.Array)
                    continue;

                foreach (var indicator in indicators.EnumerateArray())
                {
                    var type = indicator.TryGetProperty("type", out var typeEl) ? typeEl.GetString() ?? "" : "";
                    var value = indicator.TryGetProperty("indicator", out var valEl) ? valEl.GetString() ?? "" : "";
                    if (value.Length == 0) continue;
                    result.Add((type, value, pulseName));
                }
            }
        }
        catch { }
        return result;
    }


}
