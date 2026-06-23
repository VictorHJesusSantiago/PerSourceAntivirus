using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.ComHijack.Commands.ScanComHijack;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.ComHijack.Commands;

public class ScanComHijackCommandHandlerTests
{
    private static ScanComHijackCommandHandler Build(
        IComHijackMonitor? monitor = null,
        IComHijackAlertRepository? repo = null)
    {
        monitor ??= Substitute.For<IComHijackMonitor>();
        repo ??= Substitute.For<IComHijackAlertRepository>();
        return new ScanComHijackCommandHandler(monitor, repo);
    }

    [Fact]
    public async Task Handle_PersistsEachAlertIndividuallyViaAddAsync()
    {
        var monitor = Substitute.For<IComHijackMonitor>();
        var alerts = new List<ComHijackAlert>
        {
            new() { Id = 1, AlertType = "UserHive", ClsidOrPath = "{DEADBEEF-1234-5678-ABCD-000000000001}", SuspiciousPath = @"C:\Users\user\AppData\Local\evil.dll", Severity = "High" },
            new() { Id = 2, AlertType = "UserHive", ClsidOrPath = "{DEADBEEF-1234-5678-ABCD-000000000002}", SuspiciousPath = @"C:\Users\user\AppData\Roaming\persist.dll", Severity = "Critical" }
        };
        monitor.ScanCurrentStateAsync(Arg.Any<CancellationToken>()).Returns(alerts);
        var repo = Substitute.For<IComHijackAlertRepository>();

        await Build(monitor, repo).Handle(new ScanComHijackCommand(), CancellationToken.None);

        await repo.Received(2).AddAsync(Arg.Any<ComHijackAlert>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_DoesNotCallAddAsync_WhenNoAlertsFound()
    {
        var monitor = Substitute.For<IComHijackMonitor>();
        monitor.ScanCurrentStateAsync(Arg.Any<CancellationToken>()).Returns(new List<ComHijackAlert>());
        var repo = Substitute.For<IComHijackAlertRepository>();

        await Build(monitor, repo).Handle(new ScanComHijackCommand(), CancellationToken.None);

        await repo.DidNotReceive().AddAsync(Arg.Any<ComHijackAlert>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsAlertsFromMonitor()
    {
        var monitor = Substitute.For<IComHijackMonitor>();
        var alerts = new List<ComHijackAlert>
        {
            new() { Id = 3, AlertType = "SystemHive", ClsidOrPath = "{DEADBEEF-1234-5678-ABCD-000000000003}", SuspiciousPath = @"C:\Windows\Temp\injected.dll", LegitimateSystemPath = @"C:\Windows\System32\legit.dll", Severity = "Critical" }
        };
        monitor.ScanCurrentStateAsync(Arg.Any<CancellationToken>()).Returns(alerts);
        var repo = Substitute.For<IComHijackAlertRepository>();

        var result = await Build(monitor, repo).Handle(new ScanComHijackCommand(), CancellationToken.None);

        result.Should().BeEquivalentTo(alerts);
    }
}
