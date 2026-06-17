using MediatR;

namespace PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;

public class ScanDirectoryCommandHandler(FileScanService fileScanService, ScanSettings settings)
    : IRequestHandler<ScanDirectoryCommand, ScanDirectoryResult>
{
    public async Task<ScanDirectoryResult> Handle(ScanDirectoryCommand request, CancellationToken cancellationToken)
    {
        var startedAt = DateTime.UtcNow;

        IEnumerable<string> filePaths;
        if (File.Exists(request.RootPath))
        {
            filePaths = [request.RootPath];
        }
        else if (Directory.Exists(request.RootPath))
        {
            filePaths = Directory.EnumerateFiles(request.RootPath, "*", SearchOption.AllDirectories);
        }
        else
        {
            throw new DirectoryNotFoundException($"Path not found: {request.RootPath}");
        }

        var pathList = filePaths.ToList();

        // Incremental scan: load existing hashes before parallelizing (single DB read).
        var existingHashes = await fileScanService.GetExistingHashesAsync(pathList, cancellationToken);

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = settings.MaxParallelism,
            CancellationToken = cancellationToken
        };

        var analyzed = new System.Collections.Concurrent.ConcurrentBag<Domain.Entities.ScannedFile>();

        await Parallel.ForEachAsync(pathList, parallelOptions, async (filePath, ct) =>
        {
            var file = await fileScanService.AnalyzeFileAsync(filePath, existingHashes, ct);
            if (file is not null)
            {
                analyzed.Add(file);
            }
        });

        // Persist serially — DbContext is not thread-safe.
        foreach (var file in analyzed)
        {
            await fileScanService.PersistAsync(file, cancellationToken);
        }

        return new ScanDirectoryResult(analyzed.Count, DateTime.UtcNow - startedAt);
    }
}
