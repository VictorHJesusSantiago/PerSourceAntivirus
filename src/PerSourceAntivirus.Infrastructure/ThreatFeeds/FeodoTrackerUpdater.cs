using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

// Downloads Feodo Tracker aggressive CSV blocklist; extracts destination IPs and rewrites ip-blocklist.txt.
public sealed class FeodoTrackerUpdater : IThreatFeedUpdater, IDisposable
{
    public string FeedName => "Feodo Tracker";

    private const string FeedUrl =
        "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv";

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly IBlocklistProvider _provider;
    private readonly string _blocklistFile;

    public FeodoTrackerUpdater(IBlocklistProvider provider, string blocklistFile, HttpClient? http = null)
    {
        _provider      = provider;
        _blocklistFile = blocklistFile;
        _ownsHttp      = http is null;
        _http          = http ?? new HttpClient();
    }

    public async Task<ThreatFeedUpdateResult> UpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var csv  = await _http.GetStringAsync(FeedUrl, cancellationToken);
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

    // CSV columns: first_seen_utc,dst_ip,dst_port,... — comment lines start with '#'.
    internal static List<string> ParseIps(string csv)
    {
        var ips = new List<string>();
        foreach (var line in csv.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
            var parts = trimmed.Split(',');
            if (parts.Length >= 2)
            {
                var ip = parts[1].Trim();
                if (ip.Length > 0) ips.Add(ip);
            }
        }
        return ips;
    }

    public void Dispose() { if (_ownsHttp) _http.Dispose(); }
}
