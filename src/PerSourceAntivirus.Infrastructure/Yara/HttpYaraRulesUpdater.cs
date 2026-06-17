using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Yara;

public class HttpYaraRulesUpdater(IYaraScanner yaraScanner, string rulesDirectory, IReadOnlyList<string> defaultUrls) : IYaraRulesUpdater
{
    private static readonly HttpClient Http = new();

    public async Task<YaraRulesUpdateResult> UpdateAsync(string? sourceUrl = null, CancellationToken cancellationToken = default)
    {
        var urls = sourceUrl is not null
            ? (IReadOnlyList<string>)[sourceUrl]
            : defaultUrls;

        if (urls.Count == 0)
            return new YaraRulesUpdateResult(0, "none", false, "No update URLs configured. Set Yara:UpdateUrls in appsettings.json.");

        Directory.CreateDirectory(rulesDirectory);

        var filesDownloaded = 0;
        var sources = new List<string>();

        foreach (var url in urls)
        {
            try
            {
                var content = await Http.GetStringAsync(url, cancellationToken);

                var uriPath = new Uri(url).LocalPath;
                var filename = Path.GetFileName(uriPath);
                if (string.IsNullOrEmpty(filename) || (!filename.EndsWith(".yar") && !filename.EndsWith(".rules")))
                    filename = $"downloaded_{DateTime.UtcNow:yyyyMMddHHmmss}_{filesDownloaded}.yar";

                var destPath = Path.Combine(rulesDirectory, filename);
                await File.WriteAllTextAsync(destPath, content, cancellationToken);
                filesDownloaded++;
                sources.Add(url);
            }
            catch (Exception ex)
            {
                return new YaraRulesUpdateResult(filesDownloaded, url, false, ex.Message);
            }
        }

        // Reload scanner with newly downloaded rules.
        yaraScanner.Reload();

        return new YaraRulesUpdateResult(filesDownloaded, string.Join(", ", sources), true);
    }
}
