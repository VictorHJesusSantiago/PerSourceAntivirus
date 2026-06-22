using System.Collections.Concurrent;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Dga;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IDgaDetector, DgaDetector>();
public sealed class DgaDetector : IDgaDetector
{
    // NXDomain tracking: hostname → streak count
    private readonly ConcurrentDictionary<string, int> _nxdomainStreaks = new(StringComparer.OrdinalIgnoreCase);

    // Known-good domains to skip
    private static readonly HashSet<string> TrustedDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "google.com", "microsoft.com", "windows.com", "windowsupdate.com", "apple.com", "amazon.com",
        "cloudflare.com", "github.com", "githubusercontent.com", "akamai.com", "fastly.com"
    };

    public DgaAnalysisResult Analyze(string hostname)
    {
        // Skip trusted domains
        if (TrustedDomains.Contains(hostname))
            return new DgaAnalysisResult(0, 0, 0, 0.0, false);

        // Extract the 2nd-level domain label
        var label = ExtractSldLabel(hostname);

        // Skip very short or very long labels (not typical DGA pattern range)
        if (label.Length < 6 || label.Length > 20)
            return new DgaAnalysisResult(0, 0, 0, 0.0, false);

        var entropy = CalculateShannonEntropy(label);
        var cvRatio = CalculateConsonantVowelRatio(label);
        var nxStreak = _nxdomainStreaks.TryGetValue(hostname, out var streak) ? streak : 0;

        var probability = 0.0;

        // Entropy scoring
        if (entropy > 3.5) probability += 0.35;
        if (entropy > 4.0) probability += 0.15;

        // CV ratio scoring
        if (cvRatio > 4.0) probability += 0.20;
        if (cvRatio > 6.0) probability += 0.10;

        // NXDOMAIN streak scoring
        if (nxStreak >= 3) probability += 0.15;
        if (nxStreak >= 10) probability += 0.10;

        // Label length scoring
        if (label.Length > 15) probability += 0.10;

        // All consonants + digits (no vowels at all)
        if (!label.Any(c => "aeiou".Contains(char.ToLowerInvariant(c))))
            probability += 0.15;

        // Cap at 1.0
        probability = Math.Min(1.0, probability);

        var isDga = probability >= 0.60;
        return new DgaAnalysisResult(entropy, cvRatio, nxStreak, probability, isDga);
    }

    public void RecordNxdomain(string hostname)
        => _nxdomainStreaks.AddOrUpdate(hostname, 1, (_, c) => c + 1);

    private static string ExtractSldLabel(string hostname)
    {
        // Remove trailing dot if present
        hostname = hostname.TrimEnd('.');

        var parts = hostname.Split('.');
        if (parts.Length >= 2)
            return parts[^2]; // second-level domain label

        return parts[0];
    }

    private static double CalculateShannonEntropy(string label)
    {
        if (label.Length == 0)
            return 0;

        var freq = new Dictionary<char, int>();
        foreach (var c in label)
        {
            var lc = char.ToLowerInvariant(c);
            freq[lc] = freq.TryGetValue(lc, out var count) ? count + 1 : 1;
        }

        var entropy = 0.0;
        var total = (double)label.Length;
        foreach (var count in freq.Values)
        {
            var p = count / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static double CalculateConsonantVowelRatio(string label)
    {
        var vowels = 0;
        var consonants = 0;

        foreach (var c in label.ToLowerInvariant())
        {
            if (!char.IsLetter(c))
                continue; // skip digits and other chars

            if ("aeiou".Contains(c))
                vowels++;
            else
                consonants++;
        }

        return consonants / (double)(vowels + 1);
    }
}
