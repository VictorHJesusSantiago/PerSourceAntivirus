using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;

public class GetScannedFilesQueryHandler(IScannedFileRepository scannedFileRepository)
    : IRequestHandler<GetScannedFilesQuery, IReadOnlyList<ScannedFile>>
{
    public Task<IReadOnlyList<ScannedFile>> Handle(GetScannedFilesQuery request, CancellationToken cancellationToken)
        => scannedFileRepository.GetAllAsync(cancellationToken);
}
