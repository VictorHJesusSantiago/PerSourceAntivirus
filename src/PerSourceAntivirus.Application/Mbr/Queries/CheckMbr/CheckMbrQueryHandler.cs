using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Mbr.Queries.CheckMbr;

public class CheckMbrQueryHandler(
    IMbrProtectionService mbrService,
    IMbrSnapshotRepository repository)
    : IRequestHandler<CheckMbrQuery, CheckMbrResult>
{
    public async Task<CheckMbrResult> Handle(
        CheckMbrQuery request, CancellationToken cancellationToken)
    {
        var baseline = await repository.GetLatestBaselineAsync(request.DriveIndex, cancellationToken);
        var read     = await mbrService.ReadMbrHashAsync(request.DriveIndex, cancellationToken);

        if (!read.Success)
            return new CheckMbrResult(
                baseline is not null, false, null,
                baseline?.Sha256Hash, baseline?.TakenAtUtc, read.ErrorMessage);

        var matched = baseline is not null &&
            string.Equals(read.Sha256Hash, baseline.Sha256Hash, StringComparison.OrdinalIgnoreCase);

        return new CheckMbrResult(
            baseline is not null, matched,
            read.Sha256Hash, baseline?.Sha256Hash,
            baseline?.TakenAtUtc, null);
    }
}
