using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Application.Network.Queries.DetectBeaconing;

public class DetectBeaconingQueryHandler(INetworkConnectionEventRepository repository)
    : IRequestHandler<DetectBeaconingQuery, IReadOnlyList<BeaconingCandidate>>
{
    private const double BeaconingCvThreshold = 10.0;

    public async Task<IReadOnlyList<BeaconingCandidate>> Handle(
        DetectBeaconingQuery request, CancellationToken cancellationToken)
    {
        var all    = await repository.GetAllAsync(onlyBlocklisted: false, cancellationToken);
        var cutoff = DateTime.UtcNow.AddMinutes(-request.TimeWindowMinutes);

        var candidates = all
            .Where(e => e.CapturedAtUtc >= cutoff)
            .GroupBy(e => (e.SourceAddress, e.DestinationAddress, e.DestinationPort))
            .Select(g => Evaluate(g.Key.SourceAddress, g.Key.DestinationAddress, g.Key.DestinationPort,
                                  g.OrderBy(e => e.CapturedAtUtc).ToList()))
            .Where(c => c is not null && c.ConnectionCount >= request.MinConnections)
            .Cast<BeaconingCandidate>()
            .OrderBy(c => c.CoefficientOfVariationPct)
            .ToList();

        return candidates;
    }

    private static BeaconingCandidate? Evaluate(
        string src, string dst, int dstPort,
        IList<Domain.Entities.NetworkConnectionEvent> sorted)
    {
        if (sorted.Count < 2) return null;

        var intervals = new double[sorted.Count - 1];
        for (var i = 1; i < sorted.Count; i++)
            intervals[i - 1] = (sorted[i].CapturedAtUtc - sorted[i - 1].CapturedAtUtc).TotalSeconds;

        var mean = intervals.Average();
        if (mean <= 0) return null;

        var variance = intervals.Select(x => (x - mean) * (x - mean)).Average();
        var stdDev   = Math.Sqrt(variance);
        var cvPct    = stdDev / mean * 100.0;

        if (cvPct >= BeaconingCvThreshold) return null;

        return new BeaconingCandidate(
            src, dst, dstPort,
            sorted.Count,
            mean,
            cvPct,
            sorted.First().CapturedAtUtc,
            sorted.Last().CapturedAtUtc);
    }
}
