using dnYara;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Yara;

public class YaraScanner : IYaraScanner, IDisposable
{
    private readonly YaraContext? _context;
    private readonly string _rulesDirectory;
    private readonly object _lock = new();
    private CompiledRules? _compiledRules;

    public YaraScanner(string rulesDirectory)
    {
        _rulesDirectory = rulesDirectory;
        // Always initialize YARA so Reload() can compile rules even if the dir starts empty.
        _context = new YaraContext();

        if (!Directory.Exists(rulesDirectory)) return;
        var ruleFiles = Directory.GetFiles(rulesDirectory, "*.yar", SearchOption.AllDirectories);
        if (ruleFiles.Length == 0) return;

        _compiledRules = CompileRules(ruleFiles);
    }

    public IReadOnlyList<YaraRuleMatch> ScanFile(string filePath)
    {
        CompiledRules? rules;
        lock (_lock) { rules = _compiledRules; }
        if (rules is null) return [];

        // Create a Scanner per call so concurrent invocations don't share native state.
        // Scanner does not implement IDisposable; the context owns its lifetime.
        var scanner = new Scanner();
        var results = scanner.ScanFile(filePath, rules);
        return results
            .Select(r => new YaraRuleMatch(r.MatchingRule.Identifier, [.. r.MatchingRule.Tags]))
            .ToList();
    }

    public void Reload()
    {
        if (!Directory.Exists(_rulesDirectory)) return;
        var ruleFiles = Directory.GetFiles(_rulesDirectory, "*.yar", SearchOption.AllDirectories);

        CompiledRules? newRules = ruleFiles.Length > 0 ? CompileRules(ruleFiles) : null;

        lock (_lock)
        {
            var old = _compiledRules;
            _compiledRules = newRules;
            old?.Dispose();
        }
    }

    private static CompiledRules? CompileRules(string[] ruleFiles)
    {
        using var compiler = new Compiler();
        foreach (var ruleFile in ruleFiles)
        {
            var content = File.ReadAllText(ruleFile);
            compiler.AddRuleString(content);
        }
        return compiler.Compile();
    }

    public void Dispose()
    {
        lock (_lock) { _compiledRules?.Dispose(); }
        _context?.Dispose();
        GC.SuppressFinalize(this);
    }
}
