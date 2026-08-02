using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Network.Commands.SyncWfpBlocklist;

namespace PerSourceAntivirus.Application.Tests.Network.Commands;

public class SyncWfpBlocklistCommandHandlerTests
{
    private static (SyncWfpBlocklistCommandHandler handler, IWfpBlocker wfp, IBlocklistProvider blocklist, IWfpBlockRepository repo) CreateSut()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        var blocklist = Substitute.For<IBlocklistProvider>();
        var repo = Substitute.For<IWfpBlockRepository>();

        wfp.GetActiveBlocksAsync(Arg.Any<CancellationToken>()).Returns(Array.Empty<WfpBlockEntry>());
        blocklist.GetAllBlockedAddresses().Returns([]);
        repo.GetActiveIpsAsync(Arg.Any<CancellationToken>()).Returns([]);

        return (new SyncWfpBlocklistCommandHandler(wfp, blocklist, repo), wfp, blocklist, repo);
    }

    [Fact]
    public async Task Handle_PushesBlocklistProviderIpsIntoWfp()
    {
        // Regression guard: the handler used to ignore IBlocklistProvider entirely, so IPs newly
        // imported by the threat feeds never reached a WFP filter.
        var (handler, wfp, blocklist, _) = CreateSut();
        blocklist.GetAllBlockedAddresses().Returns(["192.0.2.1", "198.51.100.7"]);
        wfp.SyncFromIpListAsync(Arg.Any<IEnumerable<string>>(), Arg.Any<CancellationToken>()).Returns(2);

        var result = await handler.Handle(new SyncWfpBlocklistCommand(), CancellationToken.None);

        await wfp.Received(1).SyncFromIpListAsync(
            Arg.Is<IEnumerable<string>>(ips => ips.Contains("192.0.2.1") && ips.Contains("198.51.100.7")),
            Arg.Any<CancellationToken>());
        result.Added.Should().Be(2);
    }

    [Fact]
    public async Task Handle_UnionsBlocklistFileWithPreviouslyPersistedBlocks()
    {
        var (handler, wfp, blocklist, repo) = CreateSut();
        blocklist.GetAllBlockedAddresses().Returns(["192.0.2.1"]);
        repo.GetActiveIpsAsync(Arg.Any<CancellationToken>()).Returns(["203.0.113.9"]);

        await handler.Handle(new SyncWfpBlocklistCommand(), CancellationToken.None);

        await wfp.Received(1).SyncFromIpListAsync(
            Arg.Is<IEnumerable<string>>(ips => ips.Count() == 2),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_SkipsIpsAlreadyPresentInWfp()
    {
        var (handler, wfp, blocklist, _) = CreateSut();
        blocklist.GetAllBlockedAddresses().Returns(["192.0.2.1", "198.51.100.7"]);
        wfp.GetActiveBlocksAsync(Arg.Any<CancellationToken>())
            .Returns([new WfpBlockEntry("192.0.2.1", 1, 2, "existing", DateTime.UtcNow)]);

        var result = await handler.Handle(new SyncWfpBlocklistCommand(), CancellationToken.None);

        await wfp.Received(1).SyncFromIpListAsync(
            Arg.Is<IEnumerable<string>>(ips => ips.Single() == "198.51.100.7"),
            Arg.Any<CancellationToken>());
        result.AlreadyBlocked.Should().Be(1);
    }

    [Fact]
    public async Task Handle_ReportsErrorsWhenFewerIpsAreBlockedThanRequested()
    {
        var (handler, wfp, blocklist, _) = CreateSut();
        blocklist.GetAllBlockedAddresses().Returns(["192.0.2.1", "198.51.100.7", "203.0.113.9"]);
        wfp.SyncFromIpListAsync(Arg.Any<IEnumerable<string>>(), Arg.Any<CancellationToken>()).Returns(1);

        var result = await handler.Handle(new SyncWfpBlocklistCommand(), CancellationToken.None);

        result.Added.Should().Be(1);
        result.Errors.Should().Be(2);
    }
}
