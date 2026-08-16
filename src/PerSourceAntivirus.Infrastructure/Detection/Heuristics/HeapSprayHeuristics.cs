namespace PerSourceAntivirus.Infrastructure.Detection.Heuristics;

public static class HeapSprayHeuristics
{
    public const long OneMegabyte = 1_048_576;
    public const long HundredMegabytes = 104_857_600;

    // less entropy than normal heap data. Below ~1.5 bits/byte the region is essentially uniform.
    public const double ExtremeLowEntropyThreshold = 1.5;
    public const double LowEntropyThreshold = 3.0;

    // A spray allocates the same chunk size over and over; >50 regions in one 4 KB size bucket
    public const int UniformSizeBucketThreshold = 50;

    public static double CalculateEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;

        Span<int> frequency = stackalloc int[256];
        foreach (var b in data) frequency[b]++;

        double entropy = 0;
        foreach (var count in frequency)
        {
            if (count == 0) continue;
            double p = (double)count / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static HeapSprayVerdict? EvaluateEntropy(long totalPrivateBytes, double averageEntropy)
    {
        if (totalPrivateBytes < HundredMegabytes) return null;

        if (averageEntropy < ExtremeLowEntropyThreshold)
            return new HeapSprayVerdict("ExtremeLowEntropyLargeAlloc", 9);

        if (averageEntropy < LowEntropyThreshold)
            return new HeapSprayVerdict("LowEntropyHeapSpray", 7);

        return null;
    }

    // Groups region sizes into 4 KB buckets and reports a spray when any single bucket is
    public static HeapSprayVerdict? EvaluateUniformSizes(IReadOnlyCollection<long> regionSizes)
    {
        if (regionSizes.Count == 0) return null;

        var buckets = new Dictionary<long, int>();
        foreach (var size in regionSizes)
        {
            var bucket = size / 4096;
            buckets.TryGetValue(bucket, out var count);
            buckets[bucket] = count + 1;
        }

        return buckets.Values.Any(v => v > UniformSizeBucketThreshold)
            ? new HeapSprayVerdict("UniformSizeAlloc", 8)
            : null;
    }

    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "smss", "csrss", "wininit", "services", "lsass", "svchost"
    };

    public static bool IsSystemProcess(string processName) => SystemProcessNames.Contains(processName);
}

public record HeapSprayVerdict(string Reason, int Severity);
