using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Siem.Commands.ExportSiemBatch;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Tests.Siem.Commands;

public class ExportSiemBatchCommandHandlerTests
{
    private static ExportSiemBatchCommandHandler Build(
        ISiemExporter? exporter = null,
        IScannedFileRepository? scannedFileRepo = null,
        INetworkConnectionEventRepository? networkRepo = null,
        IRansomwareAlertRepository? ransomwareRepo = null,
        IWfpBlockRepository? wfpRepo = null)
    {
        exporter ??= Substitute.For<ISiemExporter>();
        scannedFileRepo ??= Substitute.For<IScannedFileRepository>();
        networkRepo ??= Substitute.For<INetworkConnectionEventRepository>();
        ransomwareRepo ??= Substitute.For<IRansomwareAlertRepository>();
        wfpRepo ??= Substitute.For<IWfpBlockRepository>();
        return new ExportSiemBatchCommandHandler(exporter, scannedFileRepo, networkRepo, ransomwareRepo, wfpRepo);
    }

    [Fact]
    public async Task Handle_ReturnsZeroImmediately_WhenExporterIsDisabled()
    {
        var exporter = Substitute.For<ISiemExporter>();
        exporter.IsEnabled.Returns(false);

        var result = await Build(exporter).Handle(new ExportSiemBatchCommand(), CancellationToken.None);

        result.Should().Be(0);
        await exporter.DidNotReceive().ExportBatchAsync(Arg.Any<IEnumerable<SiemEventPayload>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_CallsExportBatchAsync_WhenThereAreEvents()
    {
        var exporter = Substitute.For<ISiemExporter>();
        exporter.IsEnabled.Returns(true);

        var scannedFileRepo = Substitute.For<IScannedFileRepository>();
        var scannedFile = new ScannedFile
        {
            Id = Guid.NewGuid(),
            FilePath = @"C:\temp\evil.exe",
            FileName = "evil.exe",
            Sha256Hash = "abc123",
            ScannedAtUtc = DateTime.UtcNow,
            ThreatStatus = ThreatStatus.Malicious,
            YaraMatches = new List<YaraMatch>
            {
                new() { Id = Guid.NewGuid(), RuleIdentifier = "MalwareRule", Tags = "malicious,trojan" }
            }
        };
        scannedFileRepo.GetAllAsync(Arg.Any<CancellationToken>()).Returns(new List<ScannedFile> { scannedFile });

        var networkRepo = Substitute.For<INetworkConnectionEventRepository>();
        networkRepo.GetAllAsync(onlyBlocklisted: true, cancellationToken: Arg.Any<CancellationToken>()).Returns(new List<NetworkConnectionEvent>());

        var ransomwareRepo = Substitute.For<IRansomwareAlertRepository>();
        ransomwareRepo.GetAllAsync(onlyCritical: false, ct: Arg.Any<CancellationToken>()).Returns(new List<RansomwareAlert>());

        var wfpRepo = Substitute.For<IWfpBlockRepository>();
        wfpRepo.GetAllAsync(Arg.Any<CancellationToken>()).Returns(new List<WfpBlock>());

        await Build(exporter, scannedFileRepo, networkRepo, ransomwareRepo, wfpRepo)
            .Handle(new ExportSiemBatchCommand(), CancellationToken.None);

        await exporter.Received(1).ExportBatchAsync(Arg.Any<IEnumerable<SiemEventPayload>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsCorrectEventCount_WhenEventsExported()
    {
        var exporter = Substitute.For<ISiemExporter>();
        exporter.IsEnabled.Returns(true);

        var scannedFileRepo = Substitute.For<IScannedFileRepository>();
        var scannedFile = new ScannedFile
        {
            Id = Guid.NewGuid(),
            FilePath = @"C:\temp\evil.exe",
            FileName = "evil.exe",
            Sha256Hash = "def456",
            ScannedAtUtc = DateTime.UtcNow,
            ThreatStatus = ThreatStatus.Malicious,
            YaraMatches = new List<YaraMatch>
            {
                new() { Id = Guid.NewGuid(), RuleIdentifier = "RansomRule", Tags = "malicious,ransomware" }
            }
        };
        scannedFileRepo.GetAllAsync(Arg.Any<CancellationToken>()).Returns(new List<ScannedFile> { scannedFile });

        var networkRepo = Substitute.For<INetworkConnectionEventRepository>();
        networkRepo.GetAllAsync(onlyBlocklisted: true, cancellationToken: Arg.Any<CancellationToken>()).Returns(new List<NetworkConnectionEvent>());

        var ransomwareRepo = Substitute.For<IRansomwareAlertRepository>();
        ransomwareRepo.GetAllAsync(onlyCritical: false, ct: Arg.Any<CancellationToken>()).Returns(new List<RansomwareAlert>());

        var wfpRepo = Substitute.For<IWfpBlockRepository>();
        wfpRepo.GetAllAsync(Arg.Any<CancellationToken>()).Returns(new List<WfpBlock>());

        var result = await Build(exporter, scannedFileRepo, networkRepo, ransomwareRepo, wfpRepo)
            .Handle(new ExportSiemBatchCommand(), CancellationToken.None);

        result.Should().Be(1);
    }
}
