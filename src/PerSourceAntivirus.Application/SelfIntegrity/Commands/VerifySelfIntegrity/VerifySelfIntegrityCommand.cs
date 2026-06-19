using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.SelfIntegrity.Commands.VerifySelfIntegrity;

public record VerifySelfIntegrityCommand : IRequest<SelfIntegrityReport>;
