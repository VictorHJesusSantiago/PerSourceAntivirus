using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Uefi.Commands.ScanUefi;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Tests.Uefi.Commands;

public class ScanUefiCommandHandlerTests
{
    private static ScanUefiCommandHandler Build(
        IUefiScanner? scanner = null,
        IUefiFindingRepository? repo = null)
    {
        scanner ??= Substitute.For<IUefiScanner>();
        repo ??= Substitute.For<IUefiFindingRepository>();
        return new ScanUefiCommandHandler(scanner, repo);
    }

    [Fact]
    public async Task Handle_PersistsFindingsWhenScannerReturnsResults()
    {
        var scanner = Substitute.For<IUefiScanner>();
        var findings = new List<UefiFinding>
        {
            new() { Id = 1, TableName = "EFI_BOOT_SERVICES", SignatureName = "EvilBootkit", Description = "Suspicious UEFI module", MatchOffset = 0x1000 },
            new() { Id = 2, TableName = "EFI_RUNTIME_SERVICES", SignatureName = "PersistenceModule", Description = "UEFI persistence mechanism", MatchOffset = 0x2000 }
        };
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(findings);
        var repo = Substitute.For<IUefiFindingRepository>();

        await Build(scanner, repo).Handle(new ScanUefiCommand(), CancellationToken.None);

        await repo.Received(1).AddRangeAsync(
            Arg.Is<IEnumerable<UefiFinding>>(f => f.Count() == 2),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_DoesNotCallAddRangeAsync_WhenScannerReturnsEmptyList()
    {
        var scanner = Substitute.For<IUefiScanner>();
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(new List<UefiFinding>());
        var repo = Substitute.For<IUefiFindingRepository>();

        await Build(scanner, repo).Handle(new ScanUefiCommand(), CancellationToken.None);

        await repo.DidNotReceive().AddRangeAsync(Arg.Any<IEnumerable<UefiFinding>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsTheScannerFindings()
    {
        var scanner = Substitute.For<IUefiScanner>();
        var findings = new List<UefiFinding>
        {
            new() { Id = 3, TableName = "EFI_SYSTEM_TABLE", SignatureName = "HiddenDriver", Description = "Hidden UEFI driver", MatchOffset = 0x500 }
        };
        scanner.ScanAsync(Arg.Any<CancellationToken>()).Returns(findings);
        var repo = Substitute.For<IUefiFindingRepository>();

        var result = await Build(scanner, repo).Handle(new ScanUefiCommand(), CancellationToken.None);

        result.Should().BeEquivalentTo(findings);
    }
}
