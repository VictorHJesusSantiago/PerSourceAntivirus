using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PerSourceAntivirus.Infrastructure.ThreatFeeds;

internal sealed class FeedContentCache
{
    private readonly string _stateFile;
    private Dictionary<string, string> _hashes;

    public FeedContentCache(string stateFile)
    {
        _stateFile = stateFile;
        _hashes = Load(stateFile);
    }

    public bool HasChangedAndRecord(string feedName, string rawContent)
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawContent)));
        if (_hashes.TryGetValue(feedName, out var previous) && previous == hash) return false;

        _hashes[feedName] = hash;
        Save();
        return true;
    }

    private static Dictionary<string, string> Load(string stateFile)
    {
        try
        {
            if (!File.Exists(stateFile)) return new Dictionary<string, string>();
            var json = File.ReadAllText(stateFile);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new Dictionary<string, string>();
        }
        catch
        {
            return new Dictionary<string, string>();
        }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(_stateFile);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_stateFile, JsonSerializer.Serialize(_hashes));
        }
        catch { }
    }
}
