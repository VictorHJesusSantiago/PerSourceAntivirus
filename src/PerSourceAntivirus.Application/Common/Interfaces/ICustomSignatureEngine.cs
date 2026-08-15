using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ICustomSignatureEngine
{
    Task<IReadOnlyList<CustomSignatureMatch>> ScanFileAsync(string filePath, CancellationToken ct = default);
    void ReloadRules();
    int RuleCount { get; }
}

public record CustomSignatureRule(string Name, CustomSignatureRuleType Type, string Pattern, int Severity);

public enum CustomSignatureRuleType
{
    Hash,
    Wildcard
}
