using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Detection.Heuristics;

namespace PerSourceAntivirus.Infrastructure.Tests.Detection;

public class HeapSprayHeuristicsTests
{
    [Fact]
    public void CalculateEntropy_IsZero_ForEmptyInput()
    {
        HeapSprayHeuristics.CalculateEntropy([]).Should().Be(0);
    }

    [Fact]
    public void CalculateEntropy_IsZero_ForUniformBytes()
    {
        var sled = new byte[4096];
        Array.Fill(sled, (byte)0x90);

        HeapSprayHeuristics.CalculateEntropy(sled).Should().Be(0);
    }

    [Fact]
    public void CalculateEntropy_IsEight_ForUniformlyDistributedBytes()
    {
        var data = new byte[256 * 16];
        for (var i = 0; i < data.Length; i++) data[i] = (byte)(i % 256);

        HeapSprayHeuristics.CalculateEntropy(data).Should().BeApproximately(8.0, 0.0001);
    }

    [Fact]
    public void CalculateEntropy_IsOne_ForTwoEquallyLikelyValues()
    {
        var data = new byte[1000];
        for (var i = 0; i < data.Length; i++) data[i] = (byte)(i % 2);

        HeapSprayHeuristics.CalculateEntropy(data).Should().BeApproximately(1.0, 0.0001);
    }

    [Theory]
    [InlineData(0.5, "ExtremeLowEntropyLargeAlloc", 9)]
    [InlineData(1.49, "ExtremeLowEntropyLargeAlloc", 9)]
    [InlineData(1.5, "LowEntropyHeapSpray", 7)]
    [InlineData(2.99, "LowEntropyHeapSpray", 7)]
    public void EvaluateEntropy_Flags_LargeLowEntropyAllocations(double entropy, string reason, int severity)
    {
        var verdict = HeapSprayHeuristics.EvaluateEntropy(HeapSprayHeuristics.HundredMegabytes, entropy);

        verdict.Should().NotBeNull();
        verdict!.Reason.Should().Be(reason);
        verdict.Severity.Should().Be(severity);
    }

    [Fact]
    public void EvaluateEntropy_DoesNotFlag_NormalEntropy()
    {
        HeapSprayHeuristics.EvaluateEntropy(HeapSprayHeuristics.HundredMegabytes, 7.5)
            .Should().BeNull("ordinary heap data is high entropy and must not alert");
    }

    [Fact]
    public void EvaluateEntropy_DoesNotFlag_SmallAllocations_EvenAtZeroEntropy()
    {
        // A small zeroed buffer is completely normal; only large low-entropy regions are a spray.
        HeapSprayHeuristics.EvaluateEntropy(HeapSprayHeuristics.HundredMegabytes - 1, 0.0)
            .Should().BeNull();
    }

    [Fact]
    public void EvaluateUniformSizes_Flags_ManyIdenticallySizedRegions()
    {
        var regions = Enumerable.Repeat(1_048_576L, 51).ToList();

        var verdict = HeapSprayHeuristics.EvaluateUniformSizes(regions);

        verdict.Should().NotBeNull();
        verdict!.Reason.Should().Be("UniformSizeAlloc");
        verdict.Severity.Should().Be(8);
    }

    [Fact]
    public void EvaluateUniformSizes_DoesNotFlag_AtExactlyTheThreshold()
    {
        var regions = Enumerable.Repeat(1_048_576L, HeapSprayHeuristics.UniformSizeBucketThreshold).ToList();

        HeapSprayHeuristics.EvaluateUniformSizes(regions).Should().BeNull();
    }

    [Fact]
    public void EvaluateUniformSizes_DoesNotFlag_VariedSizes()
    {
        var regions = Enumerable.Range(1, 200).Select(i => (long)i * 4096).ToList();

        HeapSprayHeuristics.EvaluateUniformSizes(regions).Should().BeNull();
    }

    [Fact]
    public void EvaluateUniformSizes_GroupsSizesWithinTheSame4KbBucket()
    {
        var regions = Enumerable.Range(0, 60).Select(i => 1_048_576L + i).ToList();

        HeapSprayHeuristics.EvaluateUniformSizes(regions).Should().NotBeNull();
    }

    [Fact]
    public void EvaluateUniformSizes_IsNull_ForNoRegions()
    {
        HeapSprayHeuristics.EvaluateUniformSizes([]).Should().BeNull();
    }

    [Theory]
    [InlineData("svchost")]
    [InlineData("SVCHOST")]
    [InlineData("lsass")]
    [InlineData("System")]
    public void IsSystemProcess_MatchesKnownNames_CaseInsensitively(string name)
    {
        HeapSprayHeuristics.IsSystemProcess(name).Should().BeTrue();
    }

    [Theory]
    [InlineData("chrome")]
    [InlineData("notepad")]
    [InlineData("")]
    public void IsSystemProcess_IsFalse_ForOtherProcesses(string name)
    {
        HeapSprayHeuristics.IsSystemProcess(name).Should().BeFalse();
    }
}
