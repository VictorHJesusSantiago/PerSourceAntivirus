namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IOfficeMacroAnalyzer
{
    OfficeMacroData? Analyze(string filePath);
}

public record OfficeMacroData(
    bool HasMacros,
    bool HasAutoExec,
    bool HasNetworkAccess,
    bool HasProcessExecution,
    bool HasObfuscation,
    IReadOnlyList<string> SuspiciousPatterns);
