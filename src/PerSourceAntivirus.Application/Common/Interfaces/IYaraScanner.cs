namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IYaraScanner
{
    IReadOnlyList<YaraRuleMatch> ScanFile(string filePath);
    void Reload();
}

public record YaraRuleMatch(string RuleIdentifier, IReadOnlyList<string> Tags);
