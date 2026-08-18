using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Process;

namespace PerSourceAntivirus.Infrastructure.Tests.Process;

public class ShellcodeDetectorTests
{
    [Fact]
    public void AnalyzeBuffer_ReturnsNotShellcode_ForEmptyBuffer()
    {
        var result = new ShellcodeDetector().AnalyzeBuffer([], 0L);

        result.IsLikelyShellcode.Should().BeFalse();
        result.ConfidenceScore.Should().Be(0f);
    }

    [Fact]
    public void AnalyzeBuffer_DetectsMsfvenomPrologue()
    {
        var data = new byte[1024];
        data[0] = 0xFC;
        data[1] = 0x48;
        data[2] = 0x83;
        data[3] = 0xE4;
        data[4] = 0xF0;

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0x1000L);

        result.DetectedPatterns.Should().Contain("MsfvenomPrologue");
        result.ConfidenceScore.Should().BeGreaterThan(0f);
    }

    [Fact]
    public void AnalyzeBuffer_ReducesScore_ForPeHeader()
    {
        var data = new byte[1024];
        data[0] = 0x4D;
        data[1] = 0x5A;

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0L);

        result.DetectedPatterns.Should().Contain("SafeIndicator:PeHeader");
        result.ConfidenceScore.Should().Be(0f);
    }

    [Fact]
    public void AnalyzeBuffer_HighEntropyRaisesScore()
    {
        var data = Enumerable.Range(0, 256)
            .SelectMany(i => Enumerable.Repeat((byte)i, 4))
            .ToArray();

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0L);

        result.DetectedPatterns.Should().Contain(p => p.StartsWith("HighEntropy("));
    }

    [Fact]
    public void AnalyzeBuffer_DetectsCallNextInstruction()
    {
        var data = new byte[1024];
        data[0] = 0xE8;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0L);

        result.DetectedPatterns.Should().Contain("CallNextInstruction");
    }
}
