using FluentAssertions;
using PerSourceAntivirus.Infrastructure.ThreatFeeds;

namespace PerSourceAntivirus.Infrastructure.Tests.ThreatFeeds;

public class UrlhausUpdaterTests
{
    [Fact]
    public void ParseDomains_ExtractsHostnameFromHttpUrl()
    {
        var text = "http://evil.example.com/malware.exe\n";

        var domains = UrlhausUpdater.ParseDomains(text);

        domains.Should().ContainSingle().Which.Should().Be("evil.example.com");
    }

    [Fact]
    public void ParseDomains_ExtractsHostnameFromHttpsUrl()
    {
        var text = "https://malware.org/payload.zip\n";

        var domains = UrlhausUpdater.ParseDomains(text);

        domains.Should().ContainSingle().Which.Should().Be("malware.org");
    }

    [Fact]
    public void ParseDomains_DeduplicatesHosts()
    {
        var text = "http://evil.com/a\nhttp://evil.com/b\nhttps://evil.com/c\n";

        var domains = UrlhausUpdater.ParseDomains(text);

        domains.Should().ContainSingle().Which.Should().Be("evil.com");
    }

    [Fact]
    public void ParseDomains_SkipsCommentLines()
    {
        var text = "# URLhaus blocklist\nhttp://bad.com/malware\n";

        var domains = UrlhausUpdater.ParseDomains(text);

        domains.Should().ContainSingle().Which.Should().Be("bad.com");
    }

    [Fact]
    public void ParseDomains_SkipsNonUrlLines()
    {
        var text = "notaurl\n\nhttp://valid.com/x\n";

        var domains = UrlhausUpdater.ParseDomains(text);

        domains.Should().ContainSingle().Which.Should().Be("valid.com");
    }

    [Fact]
    public void ParseDomains_NormalizesToLowercase()
    {
        var text = "http://EVIL.COM/malware\n";

        var domains = UrlhausUpdater.ParseDomains(text);

        domains.Should().ContainSingle().Which.Should().Be("evil.com");
    }
}
