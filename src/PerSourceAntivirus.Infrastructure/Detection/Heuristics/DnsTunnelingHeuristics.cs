namespace PerSourceAntivirus.Infrastructure.Detection.Heuristics;

public static class DnsTunnelingHeuristics
{
    public const int MinQueriesForVolumeAlert = 40;

    public const double HighEntropyThreshold = 3.5;

    public const int LongLabelLength = 45;
    public const int MinLabelLengthForEntropyAlert = 20;
    public const int MinSamplesToJudge = 10;

    public static double CalculateLabelEntropy(string label)
    {
        if (label.Length == 0) return 0;

        var frequency = new Dictionary<char, int>();
        foreach (var c in label)
        {
            frequency.TryGetValue(c, out var count);
            frequency[c] = count + 1;
        }

        double entropy = 0;
        foreach (var count in frequency.Values)
        {
            double p = (double)count / label.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static DnsTunnelingVerdict? Evaluate(
        int queriesInWindow, int uniqueLabels, double averageEntropy, double averageLabelLength)
    {
        if (queriesInWindow < MinSamplesToJudge) return null;

        string? reason = null;
        var severity = 0;

        if (queriesInWindow >= MinQueriesForVolumeAlert && uniqueLabels >= queriesInWindow * 0.9)
        {
            reason = "HighQueryVolume";
            severity = 7;
        }

        if (averageEntropy >= HighEntropyThreshold && averageLabelLength >= MinLabelLengthForEntropyAlert)
        {
            reason = reason is null ? "HighEntropyLabels" : "HighEntropyLabels+HighQueryVolume";
            severity = 8;
        }
        else if (averageLabelLength >= LongLabelLength)
        {
            reason ??= "LongQueryNames";
            severity = Math.Max(severity, 6);
        }

        return reason is null ? null : new DnsTunnelingVerdict(reason, severity);
    }
}

public record DnsTunnelingVerdict(string Reason, int Severity);
