using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Wmi.Commands.ScanWmiPersistence;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Wmi.Commands;

public class ScanWmiPersistenceCommandHandlerTests
{
    private static ScanWmiPersistenceCommandHandler Build(
        IWmiPersistenceScanner? scanner = null,
        IWmiPersistenceAlertRepository? repo = null)
    {
        scanner ??= Substitute.For<IWmiPersistenceScanner>();
        repo ??= Substitute.For<IWmiPersistenceAlertRepository>();
        return new ScanWmiPersistenceCommandHandler(scanner, repo);
    }

    [Fact]
    public async Task Handle_PersistsAlertsWhenScannerReturnsResults()
    {
        var scanner = Substitute.For<IWmiPersistenceScanner>();
        var alerts = new List<WmiPersistenceAlert>
        {
            new() { Id = 1, FilterName = "EvilFilter", ConsumerName = "EvilConsumer", ConsumerType = "CommandLineEventConsumer", QueryLanguage = "WQL", Query = "SELECT * FROM __InstanceCreationEvent", ScriptOrCommand = "cmd.exe /c malware.exe", Severity = "High" },
            new() { Id = 2, FilterName = "BadFilter", ConsumerName = "BadConsumer", ConsumerType = "ActiveScriptEventConsumer", QueryLanguage = "WQL", Query = "SELECT * FROM __InstanceModificationEvent", ScriptOrCommand = "wscript.exe evil.vbs", Severity = "Critical" }
        };
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(alerts);
        var repo = Substitute.For<IWmiPersistenceAlertRepository>();

        await Build(scanner, repo).Handle(new ScanWmiPersistenceCommand(), CancellationToken.None);

        await repo.Received(1).AddRangeAsync(
            Arg.Is<IEnumerable<WmiPersistenceAlert>>(a => a.Count() == 2),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_DoesNotCallAddRangeAsync_WhenScannerReturnsEmptyList()
    {
        var scanner = Substitute.For<IWmiPersistenceScanner>();
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(new List<WmiPersistenceAlert>());
        var repo = Substitute.For<IWmiPersistenceAlertRepository>();

        await Build(scanner, repo).Handle(new ScanWmiPersistenceCommand(), CancellationToken.None);

        await repo.DidNotReceive().AddRangeAsync(Arg.Any<IEnumerable<WmiPersistenceAlert>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsTheScannerAlerts()
    {
        var scanner = Substitute.For<IWmiPersistenceScanner>();
        var alerts = new List<WmiPersistenceAlert>
        {
            new() { Id = 3, FilterName = "TestFilter", ConsumerName = "TestConsumer", ConsumerType = "CommandLineEventConsumer", QueryLanguage = "WQL", Query = "SELECT * FROM __InstanceCreationEvent", ScriptOrCommand = "evil.exe", Severity = "Medium" }
        };
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(alerts);
        var repo = Substitute.For<IWmiPersistenceAlertRepository>();

        var result = await Build(scanner, repo).Handle(new ScanWmiPersistenceCommand(), CancellationToken.None);

        result.Should().BeEquivalentTo(alerts);
    }
}
