using MediatR;

namespace PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;

public record ScanDirectoryCommand(string RootPath) : IRequest<ScanDirectoryResult>;
