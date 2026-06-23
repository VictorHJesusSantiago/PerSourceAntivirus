using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Rootkit.Commands.ScanRootkits;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Tests.Rootkit.Commands;

public class ScanRootkitsCommandHandlerTests
{
    private static ScanRootkitsCommandHandler Build(
        IRootkitScanner? scanner = null,
        IRootkitFindingRepository? repo = null)
    {
        scanner ??= Substitute.For<IRootkitScanner>();
        repo ??= Substitute.For<IRootkitFindingRepository>();
        return new ScanRootkitsCommandHandler(scanner, repo);
    }

    [Fact]
    public async Task Handle_PersistsFindingsWhenScannerReturnsResults()
    {
        var scanner = Substitute.For<IRootkitScanner>();
        var findings = new List<RootkitFinding>
        {
            new() { Id = 1, FindingType = RootkitFindingType.HiddenProcess, Description = "Hidden PID 1234", Severity = "High" },
            new() { Id = 2, FindingType = RootkitFindingType.SsdtHook, Description = "SSDT hook detected", Severity = "Critical" }
        };
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(findings);
        var repo = Substitute.For<IRootkitFindingRepository>();

        await Build(scanner, repo).Handle(new ScanRootkitsCommand(), CancellationToken.None);

        await repo.Received(1).AddRangeAsync(
            Arg.Is<IEnumerable<RootkitFinding>>(f => f.Count() == 2),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_DoesNotCallAddRangeAsync_WhenScannerReturnsEmptyList()
    {
        var scanner = Substitute.For<IRootkitScanner>();
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(new List<RootkitFinding>());
        var repo = Substitute.For<IRootkitFindingRepository>();

        await Build(scanner, repo).Handle(new ScanRootkitsCommand(), CancellationToken.None);

        await repo.DidNotReceive().AddRangeAsync(Arg.Any<IEnumerable<RootkitFinding>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsTheScannerFindings()
    {
        var scanner = Substitute.For<IRootkitScanner>();
        var findings = new List<RootkitFinding>
        {
            new() { Id = 3, FindingType = RootkitFindingType.HiddenDriver, Description = "Hidden driver", Severity = "High" }
        };
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(findings);
        var repo = Substitute.For<IRootkitFindingRepository>();

        var result = await Build(scanner, repo).Handle(new ScanRootkitsCommand(), CancellationToken.None);

        result.Should().BeEquivalentTo(findings);
    }
}
