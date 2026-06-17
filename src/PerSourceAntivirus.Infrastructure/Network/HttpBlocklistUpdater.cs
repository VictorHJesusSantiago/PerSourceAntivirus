using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Network;

public class HttpBlocklistUpdater(
    IBlocklistProvider blocklistProvider,
    string blocklistFilePath,
    string updateUrl) : IBlocklistUpdater
{
    // Static instance avoids socket exhaustion for a singleton updater.
    private static readonly HttpClient HttpClient = new();

    public async Task<BlocklistUpdateResult> UpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var content = await HttpClient.GetStringAsync(updateUrl, cancellationToken);

            var ips = content
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith('#') && !line.StartsWith(';'))
                .Distinct()
                .ToList();

            var lines = new List<string>
            {
                $"# Auto-updated from {updateUrl}",
                $"# Last update: {DateTime.UtcNow:O}",
                string.Empty
            };
            lines.AddRange(ips);

            await File.WriteAllLinesAsync(blocklistFilePath, lines, cancellationToken);
            blocklistProvider.Reload();

            return new BlocklistUpdateResult(ips.Count, ips.Count, updateUrl, true);
        }
        catch (Exception ex)
        {
            return new BlocklistUpdateResult(0, 0, updateUrl, false, ex.Message);
        }
    }
}
