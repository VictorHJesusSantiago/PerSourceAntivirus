using MediatR;

namespace PerSourceAntivirus.Application.Scans.Commands.RestoreFile;

public record RestoreFileCommand(Guid FileId) : IRequest<RestoreFileResult>;

public record RestoreFileResult(string RestoredPath);
