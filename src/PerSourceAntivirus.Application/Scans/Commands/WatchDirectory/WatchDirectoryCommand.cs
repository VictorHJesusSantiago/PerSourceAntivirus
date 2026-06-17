using MediatR;

namespace PerSourceAntivirus.Application.Scans.Commands.WatchDirectory;

public record WatchDirectoryCommand(string Path) : IRequest<WatchDirectoryResult>;

public record WatchDirectoryResult(int FilesScanned, int ThreatsDetected);
