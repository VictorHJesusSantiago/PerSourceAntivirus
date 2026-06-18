using FluentAssertions;
using PerSourceAntivirus.Infrastructure.ThreatFeeds;

namespace PerSourceAntivirus.Infrastructure.Tests.ThreatFeeds;

public class FeodoTrackerUpdaterTests
{
    [Fact]
    public void ParseIps_ExtractsDestinationIpFromColumn1()
    {
        var csv = """
            # first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
            2024-01-01 00:00:00,192.0.2.1,443,Offline,2024-01-01,Emotet
            2024-01-02 00:00:00,198.51.100.1,80,Online,2024-01-02,IcedID
            """;

        var ips = FeodoTrackerUpdater.ParseIps(csv);

        ips.Should().BeEquivalentTo(["192.0.2.1", "198.51.100.1"]);
    }

    [Fact]
    public void ParseIps_SkipsCommentAndEmptyLines()
    {
        var csv = "# comment\n\n2024-01-01 00:00:00,10.0.0.1,443,Offline,2024-01-01,Botnet\n";

        var ips = FeodoTrackerUpdater.ParseIps(csv);

        ips.Should().ContainSingle().Which.Should().Be("10.0.0.1");
    }

    [Fact]
    public void ParseIps_ReturnsEmpty_WhenOnlyComments()
    {
        FeodoTrackerUpdater.ParseIps("# comment\n# another\n").Should().BeEmpty();
    }

    [Fact]
    public void ParseIps_SkipsRowsWithFewerThanTwoColumns()
    {
        var csv = "onlyone\n2024-01-01,192.0.2.1,443,Offline,2024-01-01,Emotet\n";

        var ips = FeodoTrackerUpdater.ParseIps(csv);

        ips.Should().ContainSingle().Which.Should().Be("192.0.2.1");
    }
}
