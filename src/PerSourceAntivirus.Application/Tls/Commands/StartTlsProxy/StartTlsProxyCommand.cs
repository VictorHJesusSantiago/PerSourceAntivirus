using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Tls.Commands.StartTlsProxy;

public record StartTlsProxyCommand(int Port = 8080) : IRequest<TlsProxyStatus>;
