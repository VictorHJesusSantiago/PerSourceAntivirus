namespace PerSourceAntivirus.Infrastructure.Detection.Heuristics;

// Pure decision logic for heap-spray detection, split out of HeapSprayDetector.
//
// The detector itself is untestable in CI: it needs OpenProcess/VirtualQueryEx/ReadProcessMemory
// against live processes and administrator rights. But the P/Invoke layer only *gathers* data —
// every judgement about whether that data looks like a spray is arithmetic over plain values.
// Keeping the judgement here makes the part that can actually be wrong verifiable.
public static class HeapSprayHeuristics
{
    public const long OneMegabyte = 1_048_576;
    public const long HundredMegabytes = 104_857_600;

    // Sprays fill memory with a repeated NOP-sled/pointer pattern, so sampled pages carry far
    // less entropy than normal heap data. Below ~1.5 bits/byte the region is essentially uniform.
    public const double ExtremeLowEntropyThreshold = 1.5;
    public const double LowEntropyThreshold = 3.0;

    // A spray allocates the same chunk size over and over; >50 regions in one 4 KB size bucket
    // is a pattern normal allocators do not produce.
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

    // Returns null when the observed entropy is unremarkable — the caller should then fall back
    // to the uniform-size check rather than raising an entropy-based alert.
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
    // over-represented, regardless of total allocation size.
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
