using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Yara;

namespace PerSourceAntivirus.Infrastructure.Tests.Yara;

public class YaraScannerReloadTests
{
    [Fact]
    public void Reload_DoesNotThrow_WhenDirectoryExists()
    {
        var rulesDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            File.WriteAllText(Path.Combine(rulesDir, "test.yar"), """
                rule TestRule { condition: false }
                """);

            var scanner = new YaraScanner(rulesDir);
            var act = () => scanner.Reload();
            act.Should().NotThrow();
            scanner.Dispose();
        }
        finally { Directory.Delete(rulesDir, recursive: true); }
    }

    [Fact]
    public void Reload_PicksUpNewRules_AfterAddingRuleFile()
    {
        var rulesDir = Directory.CreateTempSubdirectory().FullName;
        var targetFile = Path.GetTempFileName();
        try
        {
            // Start with empty directory — no rules.
            var scanner = new YaraScanner(rulesDir);
            scanner.ScanFile(targetFile).Should().BeEmpty();

            // Add a rule that matches any file, then reload.
            File.WriteAllText(Path.Combine(rulesDir, "match_all.yar"), """
                rule MatchAll { condition: true }
                """);

            scanner.Reload();
            scanner.ScanFile(targetFile).Should().ContainSingle(m => m.RuleIdentifier == "MatchAll");
            scanner.Dispose();
        }
        finally
        {
            File.Delete(targetFile);
            Directory.Delete(rulesDir, recursive: true);
        }
    }
}
