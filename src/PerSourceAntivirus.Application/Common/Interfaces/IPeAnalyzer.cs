namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPeAnalyzer
{
    PeAnalysisData? Analyze(string filePath);
}

public record PeSectionData(string Name, uint SizeOfRawData, double Entropy);

public record PeAnalysisData(
    bool Is64Bit,
    bool IsDll,
    bool IsDotNet,
    bool IsSigned,
    IReadOnlyList<PeSectionData> Sections,
    IReadOnlyList<string> SuspiciousImports,
    IReadOnlyList<string> Anomalies);
