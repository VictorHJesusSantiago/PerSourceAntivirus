using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Tls.Commands.StopTlsProxy;

public class StopTlsProxyCommandHandler(ITlsInspector inspector)
    : IRequestHandler<StopTlsProxyCommand>
{
    public async Task Handle(StopTlsProxyCommand request, CancellationToken cancellationToken)
    {
        await inspector.StopAsync();
    }
}
