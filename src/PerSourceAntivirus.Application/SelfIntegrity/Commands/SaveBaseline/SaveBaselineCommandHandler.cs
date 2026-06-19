using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.SelfIntegrity.Commands.SaveBaseline;

public class SaveBaselineCommandHandler(ISelfIntegrityService integrityService)
    : IRequestHandler<SaveBaselineCommand, bool>
{
    public async Task<bool> Handle(SaveBaselineCommand request, CancellationToken cancellationToken)
    {
        return await integrityService.SaveBaselineAsync(cancellationToken);
    }
}
