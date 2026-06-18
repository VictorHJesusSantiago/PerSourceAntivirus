using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Network.Queries.GetWfpBlocks;

namespace PerSourceAntivirus.Application.Tests.Network.Queries;

public class GetWfpBlocksQueryHandlerTests
{
    private static GetWfpBlocksQueryHandler Build(IWfpBlocker? wfp = null)
    {
        wfp ??= Substitute.For<IWfpBlocker>();
        return new GetWfpBlocksQueryHandler(wfp);
    }

    [Fact]
    public async Task Handle_ReturnsActiveBlocks_FromBlocker()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        var blocks = new List<WfpBlockEntry>
        {
            new("1.2.3.4", 10UL, 11UL, "malware", DateTime.UtcNow),
            new("5.6.7.8", 20UL, 21UL, "botnet",  DateTime.UtcNow),
        };
        wfp.GetActiveBlocksAsync(Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<WfpBlockEntry>>(blocks));

        var result = await Build(wfp).Handle(new GetWfpBlocksQuery(), CancellationToken.None);

        result.Should().HaveCount(2);
        result[0].IpAddress.Should().Be("1.2.3.4");
        result[1].IpAddress.Should().Be("5.6.7.8");
    }

    [Fact]
    public async Task Handle_ReturnsEmptyList_WhenNoBlocksActive()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        wfp.GetActiveBlocksAsync(Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<WfpBlockEntry>>([]));

        var result = await Build(wfp).Handle(new GetWfpBlocksQuery(), CancellationToken.None);

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task Handle_DelegatesToBlocker_NotRepository()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        wfp.GetActiveBlocksAsync(Arg.Any<CancellationToken>())
           .Returns(Task.FromResult<IReadOnlyList<WfpBlockEntry>>([]));

        await Build(wfp).Handle(new GetWfpBlocksQuery(), CancellationToken.None);

        await wfp.Received(1).GetActiveBlocksAsync(Arg.Any<CancellationToken>());
    }
}
