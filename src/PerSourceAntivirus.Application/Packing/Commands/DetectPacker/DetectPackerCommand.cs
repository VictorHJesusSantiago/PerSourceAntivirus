using MediatR;

namespace PerSourceAntivirus.Application.Packing.Commands.DetectPacker;

public record DetectPackerCommand(string FilePath) : IRequest<DetectPackerResult>;

public record DetectPackerResult(string PackerName, bool IsPacked, bool WasUnpacked);
