namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISteganographyDetector
{
    bool CanAnalyze(string filePath);
    SteganographyData? Analyze(string filePath);
}

public record SteganographyData(
    double ChiSquareScore,
    double HistogramAnomalyScore,
    double ChannelEntropy,
    bool IsSuspicious,
    IReadOnlyList<string> SuspicionReasons);
