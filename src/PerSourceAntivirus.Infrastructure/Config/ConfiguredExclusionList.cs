using Microsoft.Extensions.Configuration;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Config;

public class ConfiguredExclusionList : IExclusionList
{
    private readonly IReadOnlyList<string> _excludedPaths;
    private readonly HashSet<string> _excludedExtensions;
    private readonly HashSet<string> _trustedHashes;

    public ConfiguredExclusionList(IConfiguration configuration)
    {
        _excludedPaths = ReadSection(configuration, "Scan:ExcludedPaths");

        var extensions = ReadSection(configuration, "Scan:ExcludedExtensions");
        _excludedExtensions = new HashSet<string>(extensions, StringComparer.OrdinalIgnoreCase);

        var hashes = ReadSection(configuration, "Scan:TrustedHashes");
        _trustedHashes = new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase);
    }

    public bool IsExcludedFile(string filePath)
    {
        var extension = Path.GetExtension(filePath);
        if (extension.Length > 0 && _excludedExtensions.Contains(extension))
        {
            return true;
        }

        return _excludedPaths.Any(excluded =>
            filePath.StartsWith(excluded, StringComparison.OrdinalIgnoreCase));
    }

    public bool IsWhitelistedHash(string sha256Hash)
        => _trustedHashes.Contains(sha256Hash);

    private static IReadOnlyList<string> ReadSection(IConfiguration config, string key)
        => config.GetSection(key)
            .GetChildren()
            .Select(c => c.Value ?? string.Empty)
            .Where(v => v.Length > 0)
            .ToList();
}
