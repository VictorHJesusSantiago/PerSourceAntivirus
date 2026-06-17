using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Scans.Commands.WatchDirectory;

public class WatchDirectoryCommandHandler(
    IFileSystemMonitor fileSystemMonitor,
    FileScanService fileScanService)
    : IRequestHandler<WatchDirectoryCommand, WatchDirectoryResult>
{
    public async Task<WatchDirectoryResult> Handle(WatchDirectoryCommand request, CancellationToken cancellationToken)
    {
        var filesScanned = 0;
        var threatsDetected = 0;

        await foreach (var filePath in fileSystemMonitor.WatchAsync(request.Path, cancellationToken))
        {
            var result = await fileScanService.ScanFileAsync(filePath, cancellationToken);
            if (result is not null)
            {
                filesScanned++;
                if (result.ThreatStatus != ThreatStatus.Clean)
                {
                    threatsDetected++;
                }
            }
        }

        return new WatchDirectoryResult(filesScanned, threatsDetected);
    }
}
