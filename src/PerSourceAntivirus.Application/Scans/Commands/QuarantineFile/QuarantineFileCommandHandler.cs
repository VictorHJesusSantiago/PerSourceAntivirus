using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Scans.Commands.QuarantineFile;

public class QuarantineFileCommandHandler(
    IScannedFileRepository scannedFileRepository,
    IQuarantineService quarantineService)
    : IRequestHandler<QuarantineFileCommand, QuarantineFileResult>
{
    public async Task<QuarantineFileResult> Handle(QuarantineFileCommand request, CancellationToken cancellationToken)
    {
        var file = await scannedFileRepository.GetByIdAsync(request.FileId, cancellationToken)
            ?? throw new InvalidOperationException($"File with ID {request.FileId} not found.");

        if (file.IsQuarantined)
        {
            throw new InvalidOperationException($"File is already quarantined at {file.QuarantinePath}.");
        }

        var quarantinePath = await quarantineService.QuarantineAsync(file, cancellationToken);

        file.IsQuarantined = true;
        file.QuarantinedAtUtc = DateTime.UtcNow;
        file.QuarantinePath = quarantinePath;

        await scannedFileRepository.UpdateAsync(file, cancellationToken);
        return new QuarantineFileResult(file.FilePath, quarantinePath);
    }
}
