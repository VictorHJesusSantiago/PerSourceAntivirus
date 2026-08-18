using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using PerSourceAntivirus.Infrastructure.Diagnostics;

namespace PerSourceAntivirus.Infrastructure.Tests.Diagnostics;

public class DetectorDiagnosticsTests
{
    private static DetectorDiagnostics CreateSut() => new(NullLogger<DetectorDiagnostics>.Instance);

    [Fact]
    public void GetHealthSnapshot_IsEmpty_BeforeAnythingIsRecorded()
    {
        CreateSut().GetHealthSnapshot().Should().BeEmpty();
    }

    [Fact]
    public void RecordScanCompleted_CountsScanAndStampsLastSuccess()
    {
        var sut = CreateSut();

        sut.RecordScanCompleted("HeapSprayDetector", TimeSpan.FromMilliseconds(250));

        var health = sut.GetHealthSnapshot().Should().ContainSingle().Subject;
        health.DetectorName.Should().Be("HeapSprayDetector");
        health.ScansCompleted.Should().Be(1);
        health.ScansFailed.Should().Be(0);
        health.LastSuccessfulScanUtc.Should().NotBeNull();
        health.LastScanDurationSeconds.Should().BeApproximately(0.25, 0.01);
    }

    [Fact]
    public void RecordScanFailed_CountsFailureAndKeepsReason()
    {
        var sut = CreateSut();

        sut.RecordScanFailed("DllHijackDetector", "UnauthorizedAccessException");

        var health = sut.GetHealthSnapshot().Should().ContainSingle().Subject;
        health.ScansFailed.Should().Be(1);
        health.LastFailureReason.Should().Be("UnauthorizedAccessException");
        health.LastFailureUtc.Should().NotBeNull();
        health.LastSuccessfulScanUtc.Should().BeNull();
    }

    [Fact]
    public void Counters_AreTrackedIndependentlyPerDetector()
    {
        var sut = CreateSut();

        sut.RecordScanCompleted("A", TimeSpan.Zero);
        sut.RecordScanCompleted("A", TimeSpan.Zero);
        sut.RecordScanFailed("B", "Boom");
        sut.RecordAlertRaised("B");

        var snapshot = sut.GetHealthSnapshot();
        snapshot.Should().HaveCount(2);
        snapshot.Single(h => h.DetectorName == "A").ScansCompleted.Should().Be(2);
        snapshot.Single(h => h.DetectorName == "B").ScansFailed.Should().Be(1);
        snapshot.Single(h => h.DetectorName == "B").AlertsRaised.Should().Be(1);
    }

    [Fact]
    public async Task Counters_AreAccurateUnderConcurrentWriters()
    {
        var sut = CreateSut();
        const int writers = 8;
        const int perWriter = 500;

        await Task.WhenAll(Enumerable.Range(0, writers).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < perWriter; i++)
                sut.RecordScanCompleted("Concurrent", TimeSpan.Zero);
        })));

        sut.GetHealthSnapshot().Single().ScansCompleted.Should().Be(writers * perWriter);
    }
}
