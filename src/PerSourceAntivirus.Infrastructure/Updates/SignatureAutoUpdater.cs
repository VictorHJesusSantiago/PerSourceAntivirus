using System.Text.Json;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Updates;

public class SignatureAutoUpdater : IAutoUpdater
{
    private const string DefaultManifestBaseUrl = "https://update.persourceantivirus.local/manifest.json";

    private readonly IEnumerable<IThreatFeedUpdater> _feedUpdaters;
    private readonly IYaraRulesUpdater _yaraUpdater;
    private readonly IBlocklistUpdater _blocklistUpdater;
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;

    private static readonly HttpClient SharedClient = new();

    public SignatureAutoUpdater(
        IEnumerable<IThreatFeedUpdater> feedUpdaters,
        IYaraRulesUpdater yaraUpdater,
        IBlocklistUpdater blocklistUpdater,
        HttpClient? httpClient = null)
    {
        _feedUpdaters = feedUpdaters;
        _yaraUpdater = yaraUpdater;
        _blocklistUpdater = blocklistUpdater;
        _httpClient = httpClient ?? SharedClient;
        _baseUrl = DefaultManifestBaseUrl.Replace("/manifest.json", string.Empty);
    }

    public async Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken ct = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            var versionUrl = $"{_baseUrl}/version.json";
            var response = await _httpClient.GetStringAsync(versionUrl, cts.Token);

            using var doc = JsonDocument.Parse(response);
            var root = doc.RootElement;

            var latestVersion = root.TryGetProperty("version", out var vProp) ? vProp.GetString() ?? "local" : "local";

            var components = new List<string>();
            if (root.TryGetProperty("yara_rules", out var yr) && !string.IsNullOrEmpty(yr.GetString()))
                components.Add("yara_rules");
            if (root.TryGetProperty("ip_blocklist", out var ibl) && !string.IsNullOrEmpty(ibl.GetString()))
                components.Add("ip_blocklist");
            if (root.TryGetProperty("hash_blocklist", out var hbl) && !string.IsNullOrEmpty(hbl.GetString()))
                components.Add("hash_blocklist");

            const string currentVersion = "local";
            var updateAvailable = !string.Equals(latestVersion, currentVersion, StringComparison.OrdinalIgnoreCase);

            return new UpdateCheckResult(updateAvailable, currentVersion, latestVersion, components.ToArray());
        }
        catch
        {
            return new UpdateCheckResult(false, "local", "local", []);
        }
    }

    public async Task<int> ApplyUpdatesAsync(CancellationToken ct = default)
    {
        var updated = 0;

        foreach (var feedUpdater in _feedUpdaters)
        {
            try
            {
                var result = await feedUpdater.UpdateAsync(ct);
                if (result.Success) updated++;
            }
            catch { }
        }

        try
        {
            var yaraResult = await _yaraUpdater.UpdateAsync(cancellationToken: ct);
            if (yaraResult.Success) updated++;
        }
        catch { }

        try
        {
            var blocklistResult = await _blocklistUpdater.UpdateAsync(ct);
            if (blocklistResult.Success) updated++;
        }
        catch { }

        return updated;
    }
}
