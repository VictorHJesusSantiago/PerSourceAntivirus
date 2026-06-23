using PerSourceAntivirus.Application.Common.Interfaces;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace PerSourceAntivirus.Infrastructure.Steganography;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<ISteganographyDetector, LsbSteganographyDetector>();
public sealed class LsbSteganographyDetector : ISteganographyDetector
{
    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".bmp", ".jpg", ".jpeg", ".tiff", ".gif"
    };

    public bool CanAnalyze(string filePath)
        => SupportedExtensions.Contains(Path.GetExtension(filePath));

    public SteganographyData? Analyze(string filePath)
    {
        try
        {
            using var image = Image.Load<Rgba32>(filePath);

            int width = image.Width;
            int height = image.Height;
            int totalPixels = width * height;
            bool largeImage = totalPixels > 4000 * 4000;

            // Collect R, G, B channel values (sample every 4th pixel for large images)
            int step = largeImage ? 4 : 1;
            int sampleCount = 0;

            var rValues = new List<byte>();
            var gValues = new List<byte>();
            var bValues = new List<byte>();

            image.ProcessPixelRows(accessor =>
            {
                for (int y = 0; y < height; y += step)
                {
                    var row = accessor.GetRowSpan(y);
                    for (int x = 0; x < width; x += step)
                    {
                        ref var pixel = ref row[x];
                        rValues.Add(pixel.R);
                        gValues.Add(pixel.G);
                        bValues.Add(pixel.B);
                        sampleCount++;
                    }
                }
            });

            // --- LSB Chi-Square test on R channel ---
            int count0 = 0, count1 = 0;
            foreach (var r in rValues)
            {
                if ((r & 1) == 0) count0++;
                else count1++;
            }
            double expected = sampleCount / 2.0;
            double chi = 0;
            if (expected > 0)
            {
                chi = (Math.Pow(count0 - expected, 2) + Math.Pow(count1 - expected, 2)) / expected;
            }
            double chiScore = 1.0 - Math.Exp(-chi / 100.0);

            // --- Histogram pair analysis on R channel ---
            var rHist = new int[256];
            foreach (var r in rValues) rHist[r]++;

            double pairAnomalySum = 0;
            int pairCount = 0;
            for (int i = 0; i < 256; i += 2)
            {
                int lo = rHist[i];
                int hi = rHist[i + 1];
                int denom = lo + hi + 1;
                pairAnomalySum += Math.Abs(lo - hi) / (double)denom;
                pairCount++;
            }
            double histogramAnomalyScore = pairCount > 0 ? pairAnomalySum / pairCount : 1.0;

            // --- Channel entropy on R channel ---
            double channelEntropy = ComputeEntropy(rHist, rValues.Count);

            // --- Determine suspicion ---
            var suspicionReasons = new List<string>();

            if (chiScore > 0.3)
                suspicionReasons.Add("HighChiSquareDeviation");

            // Suspicious: anomaly score < 0.05 (pairs too equal) AND image has > 1000 pixels
            if (histogramAnomalyScore < 0.05 && sampleCount > 1000)
                suspicionReasons.Add("EqualizedLsbPairs");

            // Channel entropy in range 7.5–8.0 = very uniform (suspicious for steganography)
            if (channelEntropy >= 7.5 && channelEntropy <= 8.0)
                suspicionReasons.Add("UniformChannelEntropy");

            bool isSuspicious = suspicionReasons.Count > 0;

            return new SteganographyData(
                ChiSquareScore: chiScore,
                HistogramAnomalyScore: histogramAnomalyScore,
                ChannelEntropy: channelEntropy,
                IsSuspicious: isSuspicious,
                SuspicionReasons: suspicionReasons);
        }
        catch
        {
            return null;
        }
    }

    private static double ComputeEntropy(int[] histogram, int totalCount)
    {
        if (totalCount == 0) return 0;
        double entropy = 0;
        foreach (var f in histogram)
        {
            if (f == 0) continue;
            var p = (double)f / totalCount;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
