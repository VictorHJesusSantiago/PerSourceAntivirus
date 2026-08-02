using System.Security.Cryptography;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Signatures;

public sealed class CustomSignatureEngine : ICustomSignatureEngine
{
    private const long MaxScannableBytes = 64 * 1024 * 1024; // 64 MB — wildcard scan is O(n*m) naive search
    private readonly string _rulesFile;
    private readonly object _lock = new();
    private List<CustomSignatureRule> _rules = new();

    public CustomSignatureEngine(string rulesFile)
    {
        _rulesFile = rulesFile;
        ReloadRules();
    }

    public int RuleCount { get { lock (_lock) return _rules.Count; } }

    public void ReloadRules()
    {
        var rules = new List<CustomSignatureRule>();
        if (File.Exists(_rulesFile))
        {
            foreach (var line in File.ReadAllLines(_rulesFile))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;

                var parts = trimmed.Split('|');
                if (parts.Length != 4) continue;

                if (!int.TryParse(parts[3], out var severity)) continue;

                if (parts[0].Equals("HASH", StringComparison.OrdinalIgnoreCase))
                {
                    var hash = parts[2].Trim();
                    if (hash.Length == 64) // SHA-256 hex length
                        rules.Add(new CustomSignatureRule(parts[1], CustomSignatureRuleType.Hash, hash.ToLowerInvariant(), severity));
                }
                else if (parts[0].Equals("WILDCARD", StringComparison.OrdinalIgnoreCase))
                {
                    if (TryParseWildcardPattern(parts[2].Trim(), out _))
                        rules.Add(new CustomSignatureRule(parts[1], CustomSignatureRuleType.Wildcard, parts[2].Trim(), severity));
                }
            }
        }

        lock (_lock) { _rules = rules; }
    }

    public async Task<IReadOnlyList<CustomSignatureMatch>> ScanFileAsync(string filePath, CancellationToken ct = default)
    {
        var matches = new List<CustomSignatureMatch>();
        if (!File.Exists(filePath)) return matches;

        List<CustomSignatureRule> rules;
        lock (_lock) { rules = _rules; }
        if (rules.Count == 0) return matches;

        var info = new FileInfo(filePath);
        if (info.Length == 0 || info.Length > MaxScannableBytes) return matches;

        byte[] content = await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false);
        string sha256 = Convert.ToHexStringLower(SHA256.HashData(content));
        var now = DateTime.UtcNow;

        foreach (var rule in rules)
        {
            ct.ThrowIfCancellationRequested();

            if (rule.Type == CustomSignatureRuleType.Hash)
            {
                if (sha256.Equals(rule.Pattern, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(new CustomSignatureMatch
                    {
                        Id = Guid.NewGuid(),
                        FilePath = filePath,
                        FileHashSha256 = sha256,
                        SignatureName = rule.Name,
                        MatchType = "Hash",
                        Severity = rule.Severity,
                        DetectedAtUtc = now
                    });
                }
            }
            else
            {
                if (TryParseWildcardPattern(rule.Pattern, out var pattern) && ContainsPattern(content, pattern))
                {
                    matches.Add(new CustomSignatureMatch
                    {
                        Id = Guid.NewGuid(),
                        FilePath = filePath,
                        FileHashSha256 = sha256,
                        SignatureName = rule.Name,
                        MatchType = "Wildcard",
                        Severity = rule.Severity,
                        DetectedAtUtc = now
                    });
                }
            }
        }

        return matches;
    }

    // "4D5A??904500" -> pairs of hex nibbles; "??" means wildcard byte (null = wildcard).
    internal static bool TryParseWildcardPattern(string hex, out byte?[] pattern)
    {
        pattern = Array.Empty<byte?>();
        if (hex.Length == 0 || hex.Length % 2 != 0) return false;

        var result = new byte?[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            var pair = hex.Substring(i * 2, 2);
            if (pair == "??") { result[i] = null; continue; }
            if (!byte.TryParse(pair, System.Globalization.NumberStyles.HexNumber, null, out var b)) return false;
            result[i] = b;
        }

        pattern = result;
        return true;
    }

    internal static bool ContainsPattern(byte[] haystack, byte?[] pattern)
    {
        if (pattern.Length == 0 || pattern.Length > haystack.Length) return false;

        for (int start = 0; start <= haystack.Length - pattern.Length; start++)
        {
            bool match = true;
            for (int i = 0; i < pattern.Length; i++)
            {
                if (pattern[i].HasValue && pattern[i] != haystack[start + i]) { match = false; break; }
            }
            if (match) return true;
        }

        return false;
    }
}
