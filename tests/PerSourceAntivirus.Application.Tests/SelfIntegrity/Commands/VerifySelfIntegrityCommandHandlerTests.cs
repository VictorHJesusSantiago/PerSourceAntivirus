using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.SelfIntegrity.Commands.VerifySelfIntegrity;

namespace PerSourceAntivirus.Application.Tests.SelfIntegrity.Commands;

public class VerifySelfIntegrityCommandHandlerTests
{
    private static VerifySelfIntegrityCommandHandler Build(ISelfIntegrityService? service = null)
    {
        service ??= Substitute.For<ISelfIntegrityService>();
        return new VerifySelfIntegrityCommandHandler(service);
    }

    [Fact]
    public async Task Handle_DelegatesToServiceAndReturnsIntactReport()
    {
        var service = Substitute.For<ISelfIntegrityService>();
        var report = new SelfIntegrityReport(
            IsIntact: true,
            TamperedFiles: new List<string>(),
            MissingFiles: new List<string>(),
            CheckedAtUtc: DateTime.UtcNow);
        service.VerifyAsync(Arg.Any<CancellationToken>()).Returns(report);

        var result = await Build(service).Handle(new VerifySelfIntegrityCommand(), CancellationToken.None);

        result.IsIntact.Should().BeTrue();
        result.TamperedFiles.Should().BeEmpty();
        await service.Received(1).VerifyAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsReportWithTamperedFiles_WhenIntegrityViolated()
    {
        var service = Substitute.For<ISelfIntegrityService>();
        var report = new SelfIntegrityReport(
            IsIntact: false,
            TamperedFiles: new List<string> { "PerSourceAntivirus.exe", "signatures.db" },
            MissingFiles: new List<string> { "rules.yar" },
            CheckedAtUtc: DateTime.UtcNow);
        service.VerifyAsync(Arg.Any<CancellationToken>()).Returns(report);

        var result = await Build(service).Handle(new VerifySelfIntegrityCommand(), CancellationToken.None);

        result.IsIntact.Should().BeFalse();
        result.TamperedFiles.Should().HaveCount(2);
        result.MissingFiles.Should().ContainSingle(f => f == "rules.yar");
    }
}
