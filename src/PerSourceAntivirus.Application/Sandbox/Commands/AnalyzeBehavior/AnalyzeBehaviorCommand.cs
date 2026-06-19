using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Sandbox.Commands.AnalyzeBehavior;

public record AnalyzeBehaviorCommand(string FilePath, int TimeoutSeconds = 30) : IRequest<BehaviorReport>;
