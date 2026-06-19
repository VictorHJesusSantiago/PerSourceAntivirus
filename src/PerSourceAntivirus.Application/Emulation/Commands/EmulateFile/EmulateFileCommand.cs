using MediatR;

namespace PerSourceAntivirus.Application.Emulation.Commands.EmulateFile;

public record EmulateFileCommand(string FilePath) : IRequest<EmulateFileResult>;

public record EmulateFileResult(bool IsSuspicious, int InstructionCount, IReadOnlyList<string> DetectedPatterns);
