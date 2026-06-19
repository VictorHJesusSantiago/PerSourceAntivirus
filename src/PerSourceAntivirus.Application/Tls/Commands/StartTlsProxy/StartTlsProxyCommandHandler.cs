using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Tls.Commands.StartTlsProxy;

public class StartTlsProxyCommandHandler(ITlsInspector inspector)
    : IRequestHandler<StartTlsProxyCommand, TlsProxyStatus>
{
    public async Task<TlsProxyStatus> Handle(StartTlsProxyCommand request, CancellationToken cancellationToken)
    {
        await inspector.StartAsync(request.Port, cancellationToken);
        return inspector.GetStatus();
    }
}
