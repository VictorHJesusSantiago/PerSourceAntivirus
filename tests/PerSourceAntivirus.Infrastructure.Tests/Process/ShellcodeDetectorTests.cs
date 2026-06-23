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
        // Msfvenom prologue followed by enough null bytes to keep null-ratio >= 0.5%
        var data = new byte[1024];
        data[0] = 0xFC;
        data[1] = 0x48;
        data[2] = 0x83;
        data[3] = 0xE4;
        data[4] = 0xF0;
        // remaining bytes are 0x00 by default

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0x1000L);

        result.DetectedPatterns.Should().Contain("MsfvenomPrologue");
        result.ConfidenceScore.Should().BeGreaterThan(0f);
    }

    [Fact]
    public void AnalyzeBuffer_ReducesScore_ForPeHeader()
    {
        // MZ header at the start signals a PE file — should add SafeIndicator:PeHeader
        var data = new byte[1024];
        data[0] = 0x4D; // 'M'
        data[1] = 0x5A; // 'Z'

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0L);

        result.DetectedPatterns.Should().Contain("SafeIndicator:PeHeader");
        result.ConfidenceScore.Should().Be(0f);
    }

    [Fact]
    public void AnalyzeBuffer_HighEntropyRaisesScore()
    {
        // 256 distinct byte values each repeated 4 times → uniform distribution → ~8.0 entropy
        var data = Enumerable.Range(0, 256)
            .SelectMany(i => Enumerable.Repeat((byte)i, 4))
            .ToArray();

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0L);

        result.DetectedPatterns.Should().Contain(p => p.StartsWith("HighEntropy("));
    }

    [Fact]
    public void AnalyzeBuffer_DetectsCallNextInstruction()
    {
        // CallNextInstruction pattern followed by many zeros (low null ratio won't apply because zeros are present)
        var data = new byte[1024];
        data[0] = 0xE8;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        data[4] = 0x00;
        // remaining bytes are 0x00 by default

        var result = new ShellcodeDetector().AnalyzeBuffer(data, 0L);

        result.DetectedPatterns.Should().Contain("CallNextInstruction");
    }
}
