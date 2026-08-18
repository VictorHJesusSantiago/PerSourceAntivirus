using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Detection.Heuristics;

namespace PerSourceAntivirus.Infrastructure.Tests.Detection;

public class DnsTunnelingHeuristicsTests
{
    [Fact]
    public void CalculateLabelEntropy_IsZero_ForEmptyOrSingleRepeatedCharacter()
    {
        DnsTunnelingHeuristics.CalculateLabelEntropy("").Should().Be(0);
        DnsTunnelingHeuristics.CalculateLabelEntropy("aaaaaaaa").Should().Be(0);
    }

    [Fact]
    public void CalculateLabelEntropy_IsOne_ForTwoEquallyFrequentCharacters()
    {
        DnsTunnelingHeuristics.CalculateLabelEntropy("abab").Should().BeApproximately(1.0, 0.0001);
    }

    [Fact]
    public void CalculateLabelEntropy_IsHigher_ForBase32LikeLabelsThanOrdinaryHostnames()
    {

        var encodedPayload = DnsTunnelingHeuristics.CalculateLabelEntropy("mfrggzdfmztwq2lknnwg23tp");
        var ordinaryHostname = DnsTunnelingHeuristics.CalculateLabelEntropy("wwwwww");

        encodedPayload.Should().BeGreaterThan(ordinaryHostname);
        encodedPayload.Should().BeGreaterThan(DnsTunnelingHeuristics.HighEntropyThreshold);
    }

    [Fact]
    public void Evaluate_IsNull_BelowMinimumSampleSize()
    {

        DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 9, uniqueLabels: 9, averageEntropy: 4.0, averageLabelLength: 50)
            .Should().BeNull();
    }

    [Fact]
    public void Evaluate_FlagsHighEntropyLabels()
    {
        var verdict = DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 15, uniqueLabels: 15, averageEntropy: 4.0, averageLabelLength: 30);

        verdict.Should().NotBeNull();
        verdict!.Reason.Should().Be("HighEntropyLabels");
        verdict.Severity.Should().Be(8);
    }

    [Fact]
    public void Evaluate_DoesNotFlagHighEntropy_WhenLabelsAreShort()
    {

        DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 15, uniqueLabels: 15, averageEntropy: 4.0, averageLabelLength: 8)
            .Should().BeNull();
    }

    [Fact]
    public void Evaluate_FlagsHighVolume_OnlyWhenLabelsAreMostlyUnique()
    {
        var tunneling = DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 50, uniqueLabels: 50, averageEntropy: 2.0, averageLabelLength: 10);
        tunneling.Should().NotBeNull();
        tunneling!.Reason.Should().Be("HighQueryVolume");

        DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 50, uniqueLabels: 5, averageEntropy: 2.0, averageLabelLength: 10)
            .Should().BeNull();
    }

    [Fact]
    public void Evaluate_CombinesReasons_WhenBothSignalsPresent()
    {
        var verdict = DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 60, uniqueLabels: 60, averageEntropy: 4.2, averageLabelLength: 40);

        verdict.Should().NotBeNull();
        verdict!.Reason.Should().Be("HighEntropyLabels+HighQueryVolume");
        verdict.Severity.Should().Be(8);
    }

    [Fact]
    public void Evaluate_FlagsLongQueryNames_EvenAtLowEntropy()
    {
        var verdict = DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 15, uniqueLabels: 15, averageEntropy: 1.0, averageLabelLength: 50);

        verdict.Should().NotBeNull();
        verdict!.Reason.Should().Be("LongQueryNames");
        verdict.Severity.Should().Be(6);
    }

    [Fact]
    public void Evaluate_IsNull_ForOrdinaryDnsTraffic()
    {

        DnsTunnelingHeuristics.Evaluate(
            queriesInWindow: 30, uniqueLabels: 8, averageEntropy: 2.5, averageLabelLength: 12)
            .Should().BeNull();
    }
}
