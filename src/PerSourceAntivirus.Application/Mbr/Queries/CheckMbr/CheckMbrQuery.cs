using MediatR;

namespace PerSourceAntivirus.Application.Mbr.Queries.CheckMbr;

public record CheckMbrQuery(int DriveIndex = 0) : IRequest<CheckMbrResult>;

public record CheckMbrResult(
    bool HasBaseline,
    bool HashMatched,
    string? CurrentHash,
    string? BaselineHash,
    DateTime? BaselineTakenAtUtc,
    string? ErrorMessage);
