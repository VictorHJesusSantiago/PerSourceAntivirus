using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

// Custom hash + wildcard signature engine, complementary to YARA (CLAUDE.md item "Motor de
// assinatura própria simples"). Rules are loaded from a flat text file, one per line:
//   HASH|<name>|<sha256-hex>|<severity>
//   WILDCARD|<name>|<hex-pattern with ?? as any-byte wildcard>|<severity>
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
