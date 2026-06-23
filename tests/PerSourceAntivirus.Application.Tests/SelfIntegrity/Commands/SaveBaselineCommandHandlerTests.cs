using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.SelfIntegrity.Commands.SaveBaseline;

namespace PerSourceAntivirus.Application.Tests.SelfIntegrity.Commands;

public class SaveBaselineCommandHandlerTests
{
    private static SaveBaselineCommandHandler Build(ISelfIntegrityService? service = null)
    {
        service ??= Substitute.For<ISelfIntegrityService>();
        return new SaveBaselineCommandHandler(service);
    }

    [Fact]
    public async Task Handle_ReturnsTrueWhenServiceSavesSuccessfully()
    {
        var service = Substitute.For<ISelfIntegrityService>();
        service.SaveBaselineAsync(Arg.Any<CancellationToken>()).Returns(true);

        var result = await Build(service).Handle(new SaveBaselineCommand(), CancellationToken.None);

        result.Should().BeTrue();
        await service.Received(1).SaveBaselineAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsFalseWhenServiceFails()
    {
        var service = Substitute.For<ISelfIntegrityService>();
        service.SaveBaselineAsync(Arg.Any<CancellationToken>()).Returns(false);

        var result = await Build(service).Handle(new SaveBaselineCommand(), CancellationToken.None);

        result.Should().BeFalse();
    }
}
