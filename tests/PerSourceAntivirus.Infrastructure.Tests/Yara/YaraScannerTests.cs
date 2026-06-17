using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Yara;

namespace PerSourceAntivirus.Infrastructure.Tests.Yara;

public class YaraScannerTests
{
    [Fact]
    public void ScanFile_ReturnsEmptyList_WhenRulesDirectoryDoesNotExist()
    {
        var scanner = new YaraScanner(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
        var filePath = Path.GetTempFileName();
        try
        {
            var matches = scanner.ScanFile(filePath);
            matches.Should().BeEmpty();
        }
        finally
        {
            File.Delete(filePath);
            scanner.Dispose();
        }
    }

    [Fact]
    public void ScanFile_DetectsMatch_WhenFileMatchesRule()
    {
        var rulesDir = Directory.CreateTempSubdirectory().FullName;
        var targetFile = Path.GetTempFileName();
        YaraScanner? scanner = null;
        try
        {
            var ruleContent = """
                rule TestStringMatch : suspicious
                {
                    meta:
                        description = "Test rule matching literal string"
                    strings:
                        $marker = "PERSOURCE_TEST_MARKER"
                    condition:
                        $marker
                }
                """;
            File.WriteAllText(Path.Combine(rulesDir, "test.yar"), ruleContent);
            File.WriteAllText(targetFile, "some preamble PERSOURCE_TEST_MARKER some suffix");

            scanner = new YaraScanner(rulesDir);
            var matches = scanner.ScanFile(targetFile);

            matches.Should().ContainSingle();
            matches[0].RuleIdentifier.Should().Be("TestStringMatch");
            matches[0].Tags.Should().Contain("suspicious");
        }
        finally
        {
            scanner?.Dispose();
            File.Delete(targetFile);
            Directory.Delete(rulesDir, recursive: true);
        }
    }

    [Fact]
    public void ScanFile_ReturnsEmpty_WhenFileDoesNotMatchAnyRule()
    {
        var rulesDir = Directory.CreateTempSubdirectory().FullName;
        var targetFile = Path.GetTempFileName();
        YaraScanner? scanner = null;
        try
        {
            var ruleContent = """
                rule NoMatchRule : suspicious
                {
                    strings:
                        $needle = "WILL_NOT_BE_FOUND"
                    condition:
                        $needle
                }
                """;
            File.WriteAllText(Path.Combine(rulesDir, "nomatch.yar"), ruleContent);
            File.WriteAllText(targetFile, "clean file contents");

            scanner = new YaraScanner(rulesDir);
            var matches = scanner.ScanFile(targetFile);

            matches.Should().BeEmpty();
        }
        finally
        {
            scanner?.Dispose();
            File.Delete(targetFile);
            Directory.Delete(rulesDir, recursive: true);
        }
    }
}
