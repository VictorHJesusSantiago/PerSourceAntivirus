using MediatR;

namespace PerSourceAntivirus.Application.Network.Queries.DetectBeaconing;

public record DetectBeaconingQuery(
    int TimeWindowMinutes = 60,
    int MinConnections    = 5)
    : IRequest<IReadOnlyList<BeaconingCandidate>>;

public record BeaconingCandidate(
    string   SourceAddress,
    string   DestinationAddress,
    int      DestinationPort,
    int      ConnectionCount,
    double   AverageIntervalSeconds,
    double   CoefficientOfVariationPct,
    DateTime FirstSeen,
    DateTime LastSeen);
