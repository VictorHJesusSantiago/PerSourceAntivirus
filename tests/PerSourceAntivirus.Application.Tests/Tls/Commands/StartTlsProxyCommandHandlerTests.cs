using FluentAssertions;
using NSubstitute;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Tls.Commands.StartTlsProxy;

namespace PerSourceAntivirus.Application.Tests.Tls.Commands;

public class StartTlsProxyCommandHandlerTests
{
    private static StartTlsProxyCommandHandler Build(ITlsInspector? inspector = null)
    {
        inspector ??= Substitute.For<ITlsInspector>();
        return new StartTlsProxyCommandHandler(inspector);
    }

    [Fact]
    public async Task Handle_CallsStartAsyncWithCorrectPort()
    {
        var inspector = Substitute.For<ITlsInspector>();
        inspector.GetStatus().Returns(new TlsProxyStatus(IsRunning: true, Port: 9090, CaCertThumbprint: "AABBCC"));

        await Build(inspector).Handle(new StartTlsProxyCommand(9090), CancellationToken.None);

        await inspector.Received(1).StartAsync(9090, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Handle_ReturnsStatusFromInspectorAfterStart()
    {
        var inspector = Substitute.For<ITlsInspector>();
        var status = new TlsProxyStatus(IsRunning: true, Port: 8443, CaCertThumbprint: "DDEEFF112233");
        inspector.GetStatus().Returns(status);

        var result = await Build(inspector).Handle(new StartTlsProxyCommand(8443), CancellationToken.None);

        result.IsRunning.Should().BeTrue();
        result.Port.Should().Be(8443);
        result.CaCertThumbprint.Should().Be("DDEEFF112233");
    }

    [Fact]
    public async Task Handle_UsesDefaultPort8080_WhenNoPortSpecified()
    {
        var inspector = Substitute.For<ITlsInspector>();
        inspector.GetStatus().Returns(new TlsProxyStatus(IsRunning: true, Port: 8080, CaCertThumbprint: "000000"));

        await Build(inspector).Handle(new StartTlsProxyCommand(), CancellationToken.None);

        await inspector.Received(1).StartAsync(8080, Arg.Any<CancellationToken>());
    }
}
