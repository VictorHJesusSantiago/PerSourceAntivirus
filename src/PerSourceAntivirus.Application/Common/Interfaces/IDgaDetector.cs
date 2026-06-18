namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDgaDetector
{
    DgaAnalysisResult Analyze(string hostname);
    void RecordNxdomain(string hostname);
}

public record DgaAnalysisResult(double Entropy, double CvRatio, int NxdomainStreak, double Probability, bool IsDga);
