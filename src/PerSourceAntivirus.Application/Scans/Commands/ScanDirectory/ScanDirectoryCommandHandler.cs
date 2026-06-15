using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;

public class ScanDirectoryCommandHandler(
    IFileHashCalculator hashCalculator,
    IScannedFileRepository scannedFileRepository)
    : IRequestHandler<ScanDirectoryCommand, ScanDirectoryResult>
{
    public async Task<ScanDirectoryResult> Handle(ScanDirectoryCommand request, CancellationToken cancellationToken)
    {
        var startedAt = DateTime.UtcNow;
        var filesScanned = 0;

        foreach (var filePath in Directory.EnumerateFiles(request.RootPath, "*", SearchOption.AllDirectories))
        {
            FileHashResult hashResult;
            try
            {
                hashResult = await hashCalculator.ComputeAsync(filePath, cancellationToken);
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            var scannedFile = new ScannedFile
            {
                Id = Guid.NewGuid(),
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                SizeBytes = hashResult.SizeBytes,
                Sha256Hash = hashResult.Sha256Hash,
                Entropy = hashResult.Entropy,
                ScannedAtUtc = DateTime.UtcNow,
                ThreatStatus = ThreatStatus.Unknown
            };

            await scannedFileRepository.AddAsync(scannedFile, cancellationToken);
            filesScanned++;
        }

        var duration = DateTime.UtcNow - startedAt;
        return new ScanDirectoryResult(filesScanned, duration);
    }
}
