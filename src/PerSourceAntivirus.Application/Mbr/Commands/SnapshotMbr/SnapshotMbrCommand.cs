using MediatR;

namespace PerSourceAntivirus.Application.Mbr.Commands.SnapshotMbr;

public record SnapshotMbrCommand(int DriveIndex = 0) : IRequest<SnapshotMbrResult>;

public record SnapshotMbrResult(
    Guid Id,
    int DriveIndex,
    string Sha256Hash,
    int SectorSize,
    DateTime TakenAtUtc,
    bool IsBaseline);
