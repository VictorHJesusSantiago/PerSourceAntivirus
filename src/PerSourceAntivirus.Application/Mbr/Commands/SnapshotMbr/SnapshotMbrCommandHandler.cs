using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Mbr.Commands.SnapshotMbr;

public class SnapshotMbrCommandHandler(
    IMbrProtectionService mbrService,
    IMbrSnapshotRepository repository)
    : IRequestHandler<SnapshotMbrCommand, SnapshotMbrResult>
{
    public async Task<SnapshotMbrResult> Handle(
        SnapshotMbrCommand request, CancellationToken cancellationToken)
    {
        var read = await mbrService.ReadMbrHashAsync(request.DriveIndex, cancellationToken);
        if (!read.Success || read.Sha256Hash is null)
            throw new InvalidOperationException(
                $"Failed to read MBR for drive {request.DriveIndex}: {read.ErrorMessage}");

        var existing = await repository.GetLatestBaselineAsync(request.DriveIndex, cancellationToken);

        var snapshot = new MbrSnapshot
        {
            Id         = Guid.NewGuid(),
            DriveIndex = request.DriveIndex,
            Sha256Hash = read.Sha256Hash,
            SectorSize = read.SectorSize,
            TakenAtUtc = DateTime.UtcNow,
            IsBaseline = existing is null,
        };

        await repository.AddAsync(snapshot, cancellationToken);
        return new SnapshotMbrResult(
            snapshot.Id, snapshot.DriveIndex, snapshot.Sha256Hash,
            snapshot.SectorSize, snapshot.TakenAtUtc, snapshot.IsBaseline);
    }
}
