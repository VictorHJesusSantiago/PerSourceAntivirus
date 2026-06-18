namespace PerSourceAntivirus.Application.Common.Interfaces;
public interface IShellcodeDetector
{
    ShellcodeAnalysisResult AnalyzeBuffer(byte[] data, long baseAddress);
}
public record ShellcodeAnalysisResult(
    bool IsLikelyShellcode,
    float ConfidenceScore,
    IReadOnlyList<string> DetectedPatterns,
    long BaseAddress
);
