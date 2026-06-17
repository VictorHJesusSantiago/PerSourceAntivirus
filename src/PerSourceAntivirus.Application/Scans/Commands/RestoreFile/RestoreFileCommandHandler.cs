using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Scans.Commands.RestoreFile;

public class RestoreFileCommandHandler(
    IScannedFileRepository scannedFileRepository,
    IQuarantineService quarantineService)
    : IRequestHandler<RestoreFileCommand, RestoreFileResult>
{
    public async Task<RestoreFileResult> Handle(RestoreFileCommand request, CancellationToken cancellationToken)
    {
        var file = await scannedFileRepository.GetByIdAsync(request.FileId, cancellationToken)
            ?? throw new InvalidOperationException($"File with ID {request.FileId} not found.");

        if (!file.IsQuarantined)
        {
            throw new InvalidOperationException("File is not quarantined.");
        }

        await quarantineService.RestoreAsync(file, cancellationToken);

        file.IsQuarantined = false;
        file.QuarantinedAtUtc = null;
        file.QuarantinePath = null;

        await scannedFileRepository.UpdateAsync(file, cancellationToken);
        return new RestoreFileResult(file.FilePath);
    }
}
