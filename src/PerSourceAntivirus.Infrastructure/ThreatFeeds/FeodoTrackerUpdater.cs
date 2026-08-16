using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

public sealed class FeodoTrackerUpdater : IThreatFeedUpdater
{
    public string FeedName => "Feodo Tracker";

    private const string FeedUrl =
        "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IBlocklistProvider _provider;
    private readonly string _blocklistFile;

    public FeodoTrackerUpdater(IBlocklistProvider provider, string blocklistFile, IHttpClientFactory httpClientFactory)
    {
        _provider          = provider;
        _blocklistFile     = blocklistFile;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<ThreatFeedUpdateResult> UpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var http = _httpClientFactory.CreateClient(ThreatFeedHttpClient.Name);
            var csv  = await http.GetStringAsync(FeedUrl, cancellationToken);
            var ips  = ParseIps(csv);
            await File.WriteAllLinesAsync(_blocklistFile, ips, cancellationToken);
            _provider.Reload();
            return new ThreatFeedUpdateResult(FeedName, ips.Count, ips.Count, true);
        }
        catch (Exception ex)
        {
            return new ThreatFeedUpdateResult(FeedName, 0, 0, false, ex.Message);
        }
    }

    internal static List<string> ParseIps(string csv)
    {
        var ips = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in csv.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
            var parts = trimmed.Split(',');
            if (parts.Length >= 2)
            {
                var ip = parts[1].Trim();
                if (ip.Length > 0
                    && System.Net.IPAddress.TryParse(ip, out _)
                    && seen.Add(ip))
                {
                    ips.Add(ip);
                }
            }
        }
        return ips;
    }
}
