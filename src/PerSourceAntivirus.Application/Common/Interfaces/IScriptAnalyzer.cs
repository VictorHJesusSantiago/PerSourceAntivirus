using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScriptAnalyzer
{
    ScriptAnalysisData? Analyze(string filePath);
}

public record ScriptAnalysisData(
    ScriptType ScriptType,
    bool HasObfuscation,
    bool HasNetworkAccess,
    bool HasProcessExecution,
    bool HasFileSystemAccess,
    IReadOnlyList<string> SuspiciousPatterns);
