using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Network.Commands.AddWfpBlock;
using PerSourceAntivirus.Application.Network.Commands.RemoveWfpBlock;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Network.Commands;

public class AddWfpBlockCommandHandlerTests
{
    private static AddWfpBlockCommandHandler Build(IWfpBlocker? wfp = null, IWfpBlockRepository? repo = null)
    {
        wfp ??= Substitute.For<IWfpBlocker>();
        repo ??= Substitute.For<IWfpBlockRepository>();
        return new AddWfpBlockCommandHandler(wfp, repo);
    }

    [Fact]
    public async Task Handle_AddsBlock_AndPersists_OnSuccess()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        var repo = Substitute.For<IWfpBlockRepository>();
        wfp.AddBlockAsync("1.2.3.4", "malware C2", Arg.Any<CancellationToken>())
           .Returns(new WfpBlockResult(true, 100UL, 200UL));

        var result = await Build(wfp, repo).Handle(
            new AddWfpBlockCommand("1.2.3.4", "malware C2"),
            CancellationToken.None);

        result.Success.Should().BeTrue();
        result.FilterIdOutboundV4.Should().Be(100UL);
        await repo.Received(1).AddAsync(
            Arg.Is<WfpBlock>(b => b.IpAddress == "1.2.3.4"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_DoesNotPersist_WhenBlockerFails()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        var repo = Substitute.For<IWfpBlockRepository>();
        wfp.AddBlockAsync("5.5.5.5", Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(new WfpBlockResult(false, 0UL, 0UL, "Access denied"));

        var result = await Build(wfp, repo).Handle(
            new AddWfpBlockCommand("5.5.5.5"),
            CancellationToken.None);

        result.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("Access denied");
        await repo.DidNotReceive().AddAsync(Arg.Any<WfpBlock>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_PropagatesFilterIds_FromBlocker()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        var repo = Substitute.For<IWfpBlockRepository>();
        wfp.AddBlockAsync("10.0.0.1", Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(new WfpBlockResult(true, 42UL, 43UL));

        var result = await Build(wfp, repo).Handle(
            new AddWfpBlockCommand("10.0.0.1", "test"),
            CancellationToken.None);

        result.FilterIdOutboundV4.Should().Be(42UL);
        result.FilterIdInboundV4.Should().Be(43UL);
    }
}

public class RemoveWfpBlockCommandHandlerTests
{
    private static RemoveWfpBlockCommandHandler Build(IWfpBlocker? wfp = null, IWfpBlockRepository? repo = null)
    {
        wfp ??= Substitute.For<IWfpBlocker>();
        repo ??= Substitute.For<IWfpBlockRepository>();
        return new RemoveWfpBlockCommandHandler(wfp, repo);
    }

    [Fact]
    public async Task Handle_RemovesBlock_AndDeactivatesInRepo()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        var repo = Substitute.For<IWfpBlockRepository>();
        wfp.RemoveBlockAsync("1.2.3.4", Arg.Any<CancellationToken>()).Returns(true);

        var removed = await Build(wfp, repo).Handle(
            new RemoveWfpBlockCommand("1.2.3.4"),
            CancellationToken.None);

        removed.Should().BeTrue();
        await repo.Received(1).DeactivateAsync("1.2.3.4", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsFalse_WhenIpNotBlocked()
    {
        var wfp = Substitute.For<IWfpBlocker>();
        var repo = Substitute.For<IWfpBlockRepository>();
        wfp.RemoveBlockAsync("9.9.9.9", Arg.Any<CancellationToken>()).Returns(false);

        var removed = await Build(wfp, repo).Handle(
            new RemoveWfpBlockCommand("9.9.9.9"),
            CancellationToken.None);

        removed.Should().BeFalse();
        await repo.DidNotReceive().DeactivateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
