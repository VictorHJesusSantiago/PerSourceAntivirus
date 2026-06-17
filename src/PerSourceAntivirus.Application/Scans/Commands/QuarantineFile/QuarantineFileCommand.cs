using MediatR;

namespace PerSourceAntivirus.Application.Scans.Commands.QuarantineFile;

public record QuarantineFileCommand(Guid FileId) : IRequest<QuarantineFileResult>;

public record QuarantineFileResult(string OriginalPath, string QuarantinePath);
