using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Network;

[SupportedOSPlatform("windows")]
public sealed class HostsFileBlocklistService : IHostsFileBlocklistService
{
    private const string BeginMarker = "# PerSourceAntivirus BEGIN — managed block, do not edit";
    private const string EndMarker = "# PerSourceAntivirus END";

    private readonly string _domainBlocklistFile;
    private readonly string _hostsFilePath;

    public HostsFileBlocklistService(string domainBlocklistFile, string? hostsFilePath = null)
    {
        _domainBlocklistFile = domainBlocklistFile;
        _hostsFilePath = hostsFilePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
    }

    public async Task<int> SyncAsync(CancellationToken ct = default)
    {
        if (!File.Exists(_domainBlocklistFile)) return 0;

        var domains = (await File.ReadAllLinesAsync(_domainBlocklistFile, ct).ConfigureAwait(false))
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var managedBlock = new List<string> { BeginMarker };
        foreach (var domain in domains)
        {
            managedBlock.Add($"0.0.0.0 {domain}");
            managedBlock.Add($"0.0.0.0 www.{domain}");
        }
        managedBlock.Add(EndMarker);

        await ReplaceManagedBlockAsync(managedBlock, ct).ConfigureAwait(false);
        return domains.Count;
    }

    public async Task RemoveManagedEntriesAsync(CancellationToken ct = default)
        => await ReplaceManagedBlockAsync(new List<string>(), ct).ConfigureAwait(false);

    private async Task ReplaceManagedBlockAsync(List<string> newBlock, CancellationToken ct)
    {
        List<string> existing;
        try { existing = (await File.ReadAllLinesAsync(_hostsFilePath, ct).ConfigureAwait(false)).ToList(); }
        catch (FileNotFoundException) { existing = new List<string>(); }

        var result = new List<string>();
        bool inManagedBlock = false;
        foreach (var line in existing)
        {
            if (line.TrimEnd() == BeginMarker) { inManagedBlock = true; continue; }
            if (line.TrimEnd() == EndMarker) { inManagedBlock = false; continue; }
            if (!inManagedBlock) result.Add(line);
        }

        if (newBlock.Count > 0)
        {
            if (result.Count > 0 && result[^1].Trim().Length != 0) result.Add(string.Empty);
            result.AddRange(newBlock);
        }

        await File.WriteAllLinesAsync(_hostsFilePath, result, ct).ConfigureAwait(false);
    }
}
