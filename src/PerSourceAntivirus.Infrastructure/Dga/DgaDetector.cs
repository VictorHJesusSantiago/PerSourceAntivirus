using System.Collections.Concurrent;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Dga;

public sealed class DgaDetector : IDgaDetector
{
    private readonly ConcurrentDictionary<string, int> _nxdomainStreaks = new(StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> TrustedDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "google.com", "microsoft.com", "windows.com", "windowsupdate.com", "apple.com", "amazon.com",
        "cloudflare.com", "github.com", "githubusercontent.com", "akamai.com", "fastly.com"
    };

    public DgaAnalysisResult Analyze(string hostname)
    {
        if (TrustedDomains.Contains(hostname))
            return new DgaAnalysisResult(0, 0, 0, 0.0, false);

        var label = ExtractSldLabel(hostname);

        if (label.Length < 6 || label.Length > 20)
            return new DgaAnalysisResult(0, 0, 0, 0.0, false);

        var entropy = CalculateShannonEntropy(label);
        var cvRatio = CalculateConsonantVowelRatio(label);
        var nxStreak = _nxdomainStreaks.TryGetValue(hostname, out var streak) ? streak : 0;

        var probability = 0.0;

        if (entropy > 3.5) probability += 0.35;
        if (entropy > 4.0) probability += 0.15;

        if (cvRatio > 4.0) probability += 0.20;
        if (cvRatio > 6.0) probability += 0.10;

        if (nxStreak >= 3) probability += 0.15;
        if (nxStreak >= 10) probability += 0.10;

        if (label.Length > 15) probability += 0.10;

        if (!label.Any(c => "aeiou".Contains(char.ToLowerInvariant(c))))
            probability += 0.15;

        probability = Math.Min(1.0, probability);

        var isDga = probability >= 0.60;
        return new DgaAnalysisResult(entropy, cvRatio, nxStreak, probability, isDga);
    }

    public void RecordNxdomain(string hostname)
        => _nxdomainStreaks.AddOrUpdate(hostname, 1, (_, c) => c + 1);

    private static string ExtractSldLabel(string hostname)
    {
        hostname = hostname.TrimEnd('.');

        var parts = hostname.Split('.');
        if (parts.Length >= 2)
            return parts[^2];

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
                continue;

            if ("aeiou".Contains(c))
                vowels++;
            else
                consonants++;
        }

        return consonants / (double)(vowels + 1);
    }
}
