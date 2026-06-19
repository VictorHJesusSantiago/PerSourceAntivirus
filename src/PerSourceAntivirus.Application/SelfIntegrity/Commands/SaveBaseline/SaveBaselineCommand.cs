using MediatR;

namespace PerSourceAntivirus.Application.SelfIntegrity.Commands.SaveBaseline;

public record SaveBaselineCommand : IRequest<bool>;
