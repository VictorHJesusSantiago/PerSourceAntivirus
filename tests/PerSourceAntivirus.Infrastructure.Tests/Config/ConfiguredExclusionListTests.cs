using FluentAssertions;
using Microsoft.Extensions.Configuration;
using PerSourceAntivirus.Infrastructure.Config;

namespace PerSourceAntivirus.Infrastructure.Tests.Config;

public class ConfiguredExclusionListTests
{
    private static ConfiguredExclusionList Build(
        string[]? excludedPaths = null,
        string[]? excludedExtensions = null,
        string[]? trustedHashes = null)
    {
        var pairs = new List<KeyValuePair<string, string?>>();

        for (var i = 0; i < (excludedPaths?.Length ?? 0); i++)
            pairs.Add(new($"Scan:ExcludedPaths:{i}", excludedPaths![i]));

        for (var i = 0; i < (excludedExtensions?.Length ?? 0); i++)
            pairs.Add(new($"Scan:ExcludedExtensions:{i}", excludedExtensions![i]));

        for (var i = 0; i < (trustedHashes?.Length ?? 0); i++)
            pairs.Add(new($"Scan:TrustedHashes:{i}", trustedHashes![i]));

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(pairs)
            .Build();
        return new ConfiguredExclusionList(config);
    }

    [Fact]
    public void IsExcludedFile_ReturnsFalse_WhenNoExclusionsConfigured()
    {
        var list = Build();
        list.IsExcludedFile(@"C:\Users\user\Documents\report.docx").Should().BeFalse();
    }

    [Fact]
    public void IsExcludedFile_ReturnsTrue_WhenExtensionMatches()
    {
        var list = Build(excludedExtensions: [".log", ".tmp"]);
        list.IsExcludedFile(@"C:\path\debug.log").Should().BeTrue();
        list.IsExcludedFile(@"C:\path\temp.tmp").Should().BeTrue();
        list.IsExcludedFile(@"C:\path\report.docx").Should().BeFalse();
    }

    [Fact]
    public void IsExcludedFile_ReturnsTrue_WhenPathPrefixMatches()
    {
        var list = Build(excludedPaths: [@"C:\Windows\WinSxS"]);
        list.IsExcludedFile(@"C:\Windows\WinSxS\amd64_something\file.dll").Should().BeTrue();
        list.IsExcludedFile(@"C:\Windows\System32\ntdll.dll").Should().BeFalse();
    }

    [Fact]
    public void IsExcludedFile_IsCaseInsensitive()
    {
        var list = Build(excludedExtensions: [".LOG"]);
        list.IsExcludedFile(@"C:\path\debug.log").Should().BeTrue();
        list.IsExcludedFile(@"C:\path\debug.LOG").Should().BeTrue();
    }

    [Fact]
    public void IsWhitelistedHash_ReturnsTrueForKnownHash_AndFalseForUnknown()
    {
        const string hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        var list = Build(trustedHashes: [hash]);
        list.IsWhitelistedHash(hash).Should().BeTrue();
        list.IsWhitelistedHash("differenthash").Should().BeFalse();
    }
}
