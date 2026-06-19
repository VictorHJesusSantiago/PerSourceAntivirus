using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Sandbox.Commands.AnalyzeBehavior;

public class AnalyzeBehaviorCommandHandler(IEnhancedSandboxRunner runner)
    : IRequestHandler<AnalyzeBehaviorCommand, BehaviorReport>
{
    public Task<BehaviorReport> Handle(AnalyzeBehaviorCommand request, CancellationToken cancellationToken)
        => runner.AnalyzeAsync(request.FilePath, TimeSpan.FromSeconds(request.TimeoutSeconds), cancellationToken);
}
