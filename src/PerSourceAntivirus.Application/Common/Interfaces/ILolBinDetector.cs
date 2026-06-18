namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ILolBinDetector
{
    LolBinDetectionResult? Analyze(string processName, string arguments);
    IReadOnlyList<LolBinEntry> GetKnownLolBins();
}

public record LolBinDetectionResult(string LolbinName, string Description, string MitreTechnique, int Severity);
public record LolBinEntry(string Name, string Description, string MitreTechnique, string[] SuspiciousArgPatterns);
