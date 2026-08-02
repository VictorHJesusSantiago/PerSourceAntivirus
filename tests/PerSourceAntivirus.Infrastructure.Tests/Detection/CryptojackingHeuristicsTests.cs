using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Detection.Heuristics;

namespace PerSourceAntivirus.Infrastructure.Tests.Detection;

public class CryptojackingHeuristicsTests
{
    [Theory]
    [InlineData(3333)]  // Stratum
    [InlineData(4444)]
    [InlineData(14444)] // Monero
    public void IsMiningPoolPort_RecognisesKnownPoolPorts(int port)
    {
        CryptojackingHeuristics.IsMiningPoolPort(port).Should().BeTrue();
    }

    [Theory]
    [InlineData(443)]
    [InlineData(80)]
    [InlineData(22)]
    public void IsMiningPoolPort_IsFalse_ForOrdinaryPorts(int port)
    {
        CryptojackingHeuristics.IsMiningPoolPort(port).Should().BeFalse();
    }

    [Fact]
    public void CalculateCpuPercent_IsZero_WhenNoTimeHasElapsed()
    {
        // First observation of a process: there is no previous sample to diff against, and a
        // division by zero here would otherwise produce Infinity and alert on everything.
        var at = DateTime.UtcNow;

        CryptojackingHeuristics.CalculateCpuPercent(TimeSpan.Zero, TimeSpan.FromSeconds(5), at, at, 4)
            .Should().Be(0);
    }

    [Fact]
    public void CalculateCpuPercent_IsOneHundred_WhenAllCoresAreSaturated()
    {
        var start = DateTime.UtcNow;
        var end = start.AddSeconds(10);

        // 10 s of wall time on 4 cores = 40 s of available CPU time; consuming all of it is 100%.
        CryptojackingHeuristics.CalculateCpuPercent(TimeSpan.Zero, TimeSpan.FromSeconds(40), start, end, 4)
            .Should().BeApproximately(100, 0.01);
    }

    [Fact]
    public void CalculateCpuPercent_IsTwentyFive_WhenOneOfFourCoresIsBusy()
    {
        var start = DateTime.UtcNow;
        var end = start.AddSeconds(10);

        CryptojackingHeuristics.CalculateCpuPercent(TimeSpan.Zero, TimeSpan.FromSeconds(10), start, end, 4)
            .Should().BeApproximately(25, 0.01);
    }

    [Fact]
    public void CalculateCpuPercent_ClampsAbove100()
    {
        var start = DateTime.UtcNow;
        var end = start.AddSeconds(1);

        // Sampling jitter can make measured CPU time exceed the wall window; the result must
        // still be a percentage.
        CryptojackingHeuristics.CalculateCpuPercent(TimeSpan.Zero, TimeSpan.FromSeconds(100), start, end, 1)
            .Should().Be(100);
    }

    [Fact]
    public void CalculateCpuPercent_ClampsBelowZero_WhenCountersReset()
    {
        var start = DateTime.UtcNow;
        var end = start.AddSeconds(10);

        // A recycled PID can report less CPU time than the previous sample.
        CryptojackingHeuristics.CalculateCpuPercent(TimeSpan.FromSeconds(50), TimeSpan.FromSeconds(1), start, end, 4)
            .Should().Be(0);
    }

    [Fact]
    public void Evaluate_DoesNotAlert_OnHighCpuAlone()
    {
        // Deliberate: compilers, games and video encoders all pin the CPU. Without a pool
        // connection this must stay silent, or the product is unusable.
        CryptojackingHeuristics.Evaluate(hasMiningPoolConnection: false, cpuPercent: 100)
            .Should().BeNull();
    }

    [Fact]
    public void Evaluate_RaisesHighestSeverity_WhenPoolConnectionAndHighCpuCoincide()
    {
        var verdict = CryptojackingHeuristics.Evaluate(hasMiningPoolConnection: true, cpuPercent: 95);

        verdict.Should().NotBeNull();
        verdict!.Reason.Should().Be("MiningPoolPortAndHighCpu");
        verdict.Severity.Should().Be(9);
    }

    [Fact]
    public void Evaluate_RaisesLowerSeverity_ForPoolConnectionWithoutHighCpu()
    {
        var verdict = CryptojackingHeuristics.Evaluate(hasMiningPoolConnection: true, cpuPercent: 5);

        verdict.Should().NotBeNull();
        verdict!.Reason.Should().Be("MiningPoolPort");
        verdict.Severity.Should().Be(6);
    }

    [Fact]
    public void Evaluate_TreatsTheCpuThresholdAsInclusive()
    {
        CryptojackingHeuristics.Evaluate(true, CryptojackingHeuristics.SustainedHighCpuPercent)
            .Should().NotBeNull();
        CryptojackingHeuristics.Evaluate(true, CryptojackingHeuristics.SustainedHighCpuPercent)!
            .Severity.Should().Be(9);
    }
}
