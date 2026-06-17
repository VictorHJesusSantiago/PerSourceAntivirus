using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Network;

public class StaticBlocklistProvider : IBlocklistProvider
{
    private readonly string _blocklistFilePath;
    private HashSet<string> _blockedAddresses;

    public StaticBlocklistProvider(string blocklistFilePath)
    {
        _blocklistFilePath = blocklistFilePath;
        _blockedAddresses = LoadAddresses(blocklistFilePath);
    }

    public bool TryGetBlockReason(string ipAddress, out string? reason)
    {
        if (_blockedAddresses.Contains(ipAddress))
        {
            reason = $"IP address {ipAddress} is on the blocklist";
            return true;
        }

        reason = null;
        return false;
    }

    public void Reload()
    {
        _blockedAddresses = LoadAddresses(_blocklistFilePath);
    }

    private static HashSet<string> LoadAddresses(string path)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path))
        {
            return set;
        }

        foreach (var line in File.ReadLines(path))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0 && !trimmed.StartsWith('#'))
            {
                set.Add(trimmed);
            }
        }

        return set;
    }
}
