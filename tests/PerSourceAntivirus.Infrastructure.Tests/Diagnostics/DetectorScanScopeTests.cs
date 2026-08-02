using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using PerSourceAntivirus.Infrastructure.Diagnostics;

namespace PerSourceAntivirus.Infrastructure.Tests.Diagnostics;

public class DetectorScanScopeTests
{
    private static DetectorDiagnostics CreateDiagnostics() => new(NullLogger<DetectorDiagnostics>.Instance);

    [Fact]
    public async Task RunAsync_RecordsSuccess_WhenScanCompletes()
    {
        var diagnostics = CreateDiagnostics();

        await DetectorScanScope.RunAsync(diagnostics, "Sut", () => Task.CompletedTask);

        var health = diagnostics.GetHealthSnapshot().Should().ContainSingle().Subject;
        health.ScansCompleted.Should().Be(1);
        health.ScansFailed.Should().Be(0);
    }

    [Fact]
    public async Task RunAsync_SwallowsException_SoTheMonitorLoopSurvives()
    {
        var diagnostics = CreateDiagnostics();

        // The whole point of the original bare `catch {}`: a failing scan must not kill the loop.
        var act = async () => await DetectorScanScope.RunAsync(
            diagnostics, "Sut", () => throw new InvalidOperationException("boom"));

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RunAsync_RecordsFailureWithExceptionType_InsteadOfSwallowingSilently()
    {
        var diagnostics = CreateDiagnostics();

        await DetectorScanScope.RunAsync(
            diagnostics, "Sut", () => throw new UnauthorizedAccessException());

        var health = diagnostics.GetHealthSnapshot().Should().ContainSingle().Subject;
        health.ScansFailed.Should().Be(1);
        health.LastFailureReason.Should().Be(nameof(UnauthorizedAccessException));
    }

    [Fact]
    public async Task RunAsync_PropagatesCancellation_SoShutdownIsNotTreatedAsFailure()
    {
        var diagnostics = CreateDiagnostics();

        var act = async () => await DetectorScanScope.RunAsync(
            diagnostics, "Sut", () => throw new OperationCanceledException());

        await act.Should().ThrowAsync<OperationCanceledException>();
        diagnostics.GetHealthSnapshot().Should().BeEmpty("cancellation is shutdown, not a scan failure");
    }

    [Fact]
    public void Run_SynchronousOverload_RecordsFailureWithoutThrowing()
    {
        var diagnostics = CreateDiagnostics();

        var act = () => DetectorScanScope.Run(diagnostics, "Sut", () => throw new IOException());

        act.Should().NotThrow();
        diagnostics.GetHealthSnapshot().Single().ScansFailed.Should().Be(1);
    }
}
