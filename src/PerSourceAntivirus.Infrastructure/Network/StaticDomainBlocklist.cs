using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Network;

public class StaticDomainBlocklist : IDomainBlocklist
{
    private readonly HashSet<string> _entries;

    public StaticDomainBlocklist(string blocklistFilePath)
    {
        _entries = LoadEntries(blocklistFilePath);
    }

    public bool IsSuspiciousDomain(string domain, out string? reason)
    {
        domain = domain.ToLowerInvariant().TrimEnd('.');

        if (_entries.Contains(domain))
        {
            reason = "Domain on blocklist";
            return true;
        }

        // Check parent domain suffixes (e.g., sub.evil.com matches .evil.com)
        var parts = domain.Split('.');
        for (var i = 1; i < parts.Length - 1; i++)
        {
            var suffix = "." + string.Join(".", parts[i..]);
            if (_entries.Contains(suffix))
            {
                reason = $"Matches blocked domain suffix {suffix}";
                return true;
            }
        }

        reason = null;
        return false;
    }

    private static HashSet<string> LoadEntries(string path)
    {
        if (!File.Exists(path)) return [];
        return File.ReadAllLines(path)
            .Select(l => l.Trim().ToLowerInvariant())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .ToHashSet();
    }
}
