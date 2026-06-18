using FluentAssertions;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Application.Network.Queries.DetectBeaconing;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Application.Tests.Network.Queries;

public class DetectBeaconingQueryHandlerTests
{
    // ------------------------------------------------------------------ helpers

    private static DetectBeaconingQueryHandler BuildHandler(
        IEnumerable<NetworkConnectionEvent> events)
        => new(new FakeNetworkConnectionEventRepository(events));

    private static NetworkConnectionEvent MakeEvent(
        string src, string dst, int dstPort, DateTime capturedAt)
        => new()
        {
            Id                 = Guid.NewGuid(),
            SourceAddress      = src,
            SourcePort         = 54321,
            DestinationAddress = dst,
            DestinationPort    = dstPort,
            CapturedAtUtc      = capturedAt,
            Protocol           = NetworkProtocol.Tcp,
            PacketLength       = 64,
        };

    // ------------------------------------------------------------------ tests

    [Fact]
    public async Task Handle_ReturnsEmpty_WhenNoEvents()
    {
        var handler = BuildHandler([]);
        var result  = await handler.Handle(new DetectBeaconingQuery(), CancellationToken.None);
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task Handle_DetectsBeaconing_WhenIntervalsAreRegular()
    {
        // 10 events exactly 60 s apart → CV = 0 % → flagged
        var baseTime = DateTime.UtcNow.AddMinutes(-25);
        var events = Enumerable.Range(0, 10)
            .Select(i => MakeEvent("192.168.1.10", "10.0.0.1", 443, baseTime.AddSeconds(i * 60.0)))
            .ToList();

        var handler = BuildHandler(events);
        var result  = await handler.Handle(new DetectBeaconingQuery(60, 5), CancellationToken.None);

        result.Should().HaveCount(1);
        result[0].SourceAddress.Should().Be("192.168.1.10");
        result[0].DestinationAddress.Should().Be("10.0.0.1");
        result[0].CoefficientOfVariationPct.Should().BeApproximately(0.0, 0.001);
        result[0].ConnectionCount.Should().Be(10);
        result[0].AverageIntervalSeconds.Should().BeApproximately(60.0, 0.001);
    }

    [Fact]
    public async Task Handle_DoesNotDetect_WhenIntervalsAreIrregular()
    {
        // Highly variable intervals → CV > 10 %
        var baseTime = DateTime.UtcNow.AddMinutes(-30);
        var offsets  = new[] { 0, 5, 60, 65, 300, 305, 900, 905, 1800, 1801 };
        var events   = offsets
            .Select(s => MakeEvent("192.168.1.10", "10.0.0.1", 80, baseTime.AddSeconds(s)))
            .ToList();

        var handler = BuildHandler(events);
        var result  = await handler.Handle(new DetectBeaconingQuery(60, 5), CancellationToken.None);

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task Handle_DoesNotDetect_WhenBelowMinConnections()
    {
        var baseTime = DateTime.UtcNow.AddMinutes(-10);
        var events = Enumerable.Range(0, 4)   // only 4 events, MinConnections=5
            .Select(i => MakeEvent("192.168.1.10", "10.0.0.1", 443, baseTime.AddSeconds(i * 60.0)))
            .ToList();

        var handler = BuildHandler(events);
        var result  = await handler.Handle(new DetectBeaconingQuery(60, 5), CancellationToken.None);

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task Handle_DoesNotDetect_WhenEventsOutsideTimeWindow()
    {
        var oldBase = DateTime.UtcNow.AddMinutes(-200);
        var events = Enumerable.Range(0, 10)
            .Select(i => MakeEvent("192.168.1.10", "10.0.0.1", 443, oldBase.AddSeconds(i * 60.0)))
            .ToList();

        var handler = BuildHandler(events);
        var result  = await handler.Handle(new DetectBeaconingQuery(60, 5), CancellationToken.None);

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task Handle_OnlyFlagsRegularPair_WhenMixedData()
    {
        var baseTime  = DateTime.UtcNow.AddMinutes(-25);

        // Regular pair: 8 events, 60 s apart
        var regularEvents = Enumerable.Range(0, 8)
            .Select(i => MakeEvent("10.1.1.1", "10.2.2.2", 4444, baseTime.AddSeconds(i * 60.0)))
            .ToList();

        // Irregular pair: same count but random-ish intervals
        var irregular = new[] { 0, 2, 50, 120, 250, 310, 800, 810 };
        var irregularEvents = irregular
            .Select(s => MakeEvent("10.1.1.1", "10.3.3.3", 80, baseTime.AddSeconds(s)))
            .ToList();

        var handler = BuildHandler(regularEvents.Concat(irregularEvents));
        var result  = await handler.Handle(new DetectBeaconingQuery(60, 5), CancellationToken.None);

        result.Should().HaveCount(1);
        result[0].DestinationAddress.Should().Be("10.2.2.2");
    }

    [Fact]
    public async Task Handle_OrdersByCoefficientOfVariation_Ascending()
    {
        var baseTime = DateTime.UtcNow.AddMinutes(-25);

        // Two regular pairs with slightly different CVs
        var pair1 = Enumerable.Range(0, 10)   // exactly 60 s → CV=0
            .Select(i => MakeEvent("10.0.0.1", "20.0.0.1", 443, baseTime.AddSeconds(i * 60.0)));

        // CV ≈ 3 %: 60 s ± 1.8 s jitter (std≈1.8, mean≈60)
        var intervals2 = new[] { 58.0, 60, 62, 59, 61, 58, 62, 60, 61 };
        var times2 = new List<DateTime> { baseTime };
        foreach (var iv in intervals2) times2.Add(times2[^1].AddSeconds(iv));
        var pair2 = times2.Select(t => MakeEvent("10.0.0.2", "20.0.0.2", 443, t));

        var handler = BuildHandler(pair1.Concat(pair2));
        var result  = await handler.Handle(new DetectBeaconingQuery(60, 5), CancellationToken.None);

        result.Should().HaveCount(2);
        result[0].CoefficientOfVariationPct
            .Should().BeLessThanOrEqualTo(result[1].CoefficientOfVariationPct);
    }

    // ------------------------------------------------------------------ fake repo

    private sealed class FakeNetworkConnectionEventRepository(
        IEnumerable<NetworkConnectionEvent> events) : INetworkConnectionEventRepository
    {
        private readonly IReadOnlyList<NetworkConnectionEvent> _events = events.ToList();

        public Task AddRangeAsync(IEnumerable<NetworkConnectionEvent> evts, CancellationToken ct)
            => Task.CompletedTask;

        public Task<IReadOnlyList<NetworkConnectionEvent>> GetAllAsync(bool onlyBlocklisted, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<NetworkConnectionEvent>>(
                onlyBlocklisted ? _events.Where(e => e.IsBlocklisted).ToList() : (IReadOnlyList<NetworkConnectionEvent>)_events);
    }
}
