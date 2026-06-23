using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Updates.Commands.CheckUpdates;

namespace PerSourceAntivirus.Application.Tests.Updates.Commands;

public class CheckUpdatesCommandHandlerTests
{
    private static CheckUpdatesCommandHandler Build(IAutoUpdater? autoUpdater = null)
    {
        autoUpdater ??= Substitute.For<IAutoUpdater>();
        return new CheckUpdatesCommandHandler(autoUpdater);
    }

    [Fact]
    public async Task Handle_DelegatesToUpdaterAndReturnsUpdateAvailableResult()
    {
        var autoUpdater = Substitute.For<IAutoUpdater>();
        var result = new UpdateCheckResult(
            UpdateAvailable: true,
            CurrentVersion: "1.0.0",
            LatestVersion: "1.1.0",
            UpdatedComponents: new[] { "signatures", "engine" });
        autoUpdater.CheckForUpdatesAsync(Arg.Any<CancellationToken>()).Returns(result);

        var actual = await Build(autoUpdater).Handle(new CheckUpdatesCommand(), CancellationToken.None);

        actual.UpdateAvailable.Should().BeTrue();
        actual.LatestVersion.Should().Be("1.1.0");
        actual.UpdatedComponents.Should().Contain("signatures");
        await autoUpdater.Received(1).CheckForUpdatesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsResultWithUpdateAvailableFalse_WhenNoUpdateFound()
    {
        var autoUpdater = Substitute.For<IAutoUpdater>();
        var result = new UpdateCheckResult(
            UpdateAvailable: false,
            CurrentVersion: "1.1.0",
            LatestVersion: "1.1.0",
            UpdatedComponents: Array.Empty<string>());
        autoUpdater.CheckForUpdatesAsync(Arg.Any<CancellationToken>()).Returns(result);

        var actual = await Build(autoUpdater).Handle(new CheckUpdatesCommand(), CancellationToken.None);

        actual.UpdateAvailable.Should().BeFalse();
        actual.UpdatedComponents.Should().BeEmpty();
    }
}
