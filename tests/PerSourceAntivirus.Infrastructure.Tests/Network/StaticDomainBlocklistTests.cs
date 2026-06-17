using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Network;

namespace PerSourceAntivirus.Infrastructure.Tests.Network;

public class StaticDomainBlocklistTests
{
    [Fact]
    public async Task IsSuspiciousDomain_ReturnsTrue_ForExactMatch()
    {
        var file = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(file, "evil-c2.example.com");
            var blocklist = new StaticDomainBlocklist(file);
            blocklist.IsSuspiciousDomain("evil-c2.example.com", out _).Should().BeTrue();
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task IsSuspiciousDomain_ReturnsFalse_ForUnlistedDomain()
    {
        var file = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(file, "# empty\n");
            var blocklist = new StaticDomainBlocklist(file);
            blocklist.IsSuspiciousDomain("safe.example.com", out _).Should().BeFalse();
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task IsSuspiciousDomain_ReturnsTrue_ForSuffixMatch()
    {
        var file = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(file, ".bad-domain.example");
            var blocklist = new StaticDomainBlocklist(file);
            blocklist.IsSuspiciousDomain("sub.bad-domain.example", out var reason).Should().BeTrue();
            reason.Should().NotBeNullOrEmpty();
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void IsSuspiciousDomain_DoesNotThrow_WhenFileDoesNotExist()
    {
        var blocklist = new StaticDomainBlocklist(Path.Combine(Path.GetTempPath(), "no_domain_list.txt"));
        var act = () => blocklist.IsSuspiciousDomain("anything.com", out _);
        act.Should().NotThrow();
    }
}
