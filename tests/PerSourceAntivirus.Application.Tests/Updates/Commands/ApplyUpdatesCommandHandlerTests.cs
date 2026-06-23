using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Updates.Commands.ApplyUpdates;

namespace PerSourceAntivirus.Application.Tests.Updates.Commands;

public class ApplyUpdatesCommandHandlerTests
{
    private static ApplyUpdatesCommandHandler Build(IAutoUpdater? autoUpdater = null)
    {
        autoUpdater ??= Substitute.For<IAutoUpdater>();
        return new ApplyUpdatesCommandHandler(autoUpdater);
    }

    [Fact]
    public async Task Handle_ReturnsCountOfAppliedUpdates()
    {
        var autoUpdater = Substitute.For<IAutoUpdater>();
        autoUpdater.ApplyUpdatesAsync(Arg.Any<CancellationToken>()).Returns(3);

        var result = await Build(autoUpdater).Handle(new ApplyUpdatesCommand(), CancellationToken.None);

        result.Should().Be(3);
        await autoUpdater.Received(1).ApplyUpdatesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsZero_WhenNothingToApply()
    {
        var autoUpdater = Substitute.For<IAutoUpdater>();
        autoUpdater.ApplyUpdatesAsync(Arg.Any<CancellationToken>()).Returns(0);

        var result = await Build(autoUpdater).Handle(new ApplyUpdatesCommand(), CancellationToken.None);

        result.Should().Be(0);
    }
}
