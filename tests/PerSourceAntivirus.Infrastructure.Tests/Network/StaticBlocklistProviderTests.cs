using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Network;

namespace PerSourceAntivirus.Infrastructure.Tests.Network;

public class StaticBlocklistProviderTests
{
    [Fact]
    public void TryGetBlockReason_ReturnsTrue_ForListedIp()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            File.WriteAllLines(filePath, ["# comment", "198.51.100.23", "203.0.113.12"]);
            var provider = new StaticBlocklistProvider(filePath);

            var blocked = provider.TryGetBlockReason("198.51.100.23", out var reason);

            blocked.Should().BeTrue();
            reason.Should().Contain("198.51.100.23");
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public void TryGetBlockReason_ReturnsFalse_ForUnlistedIp()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            File.WriteAllLines(filePath, ["198.51.100.23"]);
            var provider = new StaticBlocklistProvider(filePath);

            var blocked = provider.TryGetBlockReason("1.2.3.4", out var reason);

            blocked.Should().BeFalse();
            reason.Should().BeNull();
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public void TryGetBlockReason_IgnoresCommentLines()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            File.WriteAllLines(filePath, ["# 10.0.0.1"]);
            var provider = new StaticBlocklistProvider(filePath);

            var blocked = provider.TryGetBlockReason("10.0.0.1", out _);

            blocked.Should().BeFalse();
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public void Constructor_DoesNotThrow_WhenFileDoesNotExist()
    {
        var action = () => new StaticBlocklistProvider(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
        action.Should().NotThrow();
    }
}
