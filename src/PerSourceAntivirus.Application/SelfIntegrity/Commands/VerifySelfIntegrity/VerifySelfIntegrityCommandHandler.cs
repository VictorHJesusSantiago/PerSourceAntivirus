using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.SelfIntegrity.Commands.VerifySelfIntegrity;

public class VerifySelfIntegrityCommandHandler(ISelfIntegrityService integrityService)
    : IRequestHandler<VerifySelfIntegrityCommand, SelfIntegrityReport>
{
    public async Task<SelfIntegrityReport> Handle(
        VerifySelfIntegrityCommand request, CancellationToken cancellationToken)
    {
        return await integrityService.VerifyAsync(cancellationToken);
    }
}
