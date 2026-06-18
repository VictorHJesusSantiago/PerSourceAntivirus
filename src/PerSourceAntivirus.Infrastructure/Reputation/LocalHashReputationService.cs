using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Reputation;

public class LocalHashReputationService : IHashReputationService
{
    private readonly string _blocklistFilePath;
    private volatile HashSet<string> _knownMalicious;

    public LocalHashReputationService(string blocklistFilePath)
    {
        _blocklistFilePath = blocklistFilePath;
        _knownMalicious = LoadHashes(blocklistFilePath);
    }

    public Task<HashReputationData?> CheckAsync(string sha256, CancellationToken cancellationToken = default)
    {
        var hash = sha256.ToLowerInvariant();
        HashReputationData? result = _knownMalicious.Contains(hash)
            ? new HashReputationData(1, 1, true, "LocalList", null)
            : null;
        return Task.FromResult(result);
    }

    public void Reload() => _knownMalicious = LoadHashes(_blocklistFilePath);

    private static HashSet<string> LoadHashes(string path)
    {
        if (!File.Exists(path)) return [];
        return File.ReadAllLines(path)
            .Select(l => l.Trim().ToLowerInvariant())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .ToHashSet();
    }
}
