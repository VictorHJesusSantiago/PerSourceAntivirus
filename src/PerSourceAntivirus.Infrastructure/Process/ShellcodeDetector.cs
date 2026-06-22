using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Process;

public class ShellcodeDetector : IShellcodeDetector
{
    private static readonly byte[] PatternMsfvenom = [0xFC, 0x48, 0x83, 0xE4, 0xF0];
    private static readonly byte[] PatternCallNext = [0xE8, 0x00, 0x00, 0x00, 0x00];
    private static readonly byte[] PatternCallRax = [0xFF, 0xD0];
    private static readonly byte[] PatternCallRcx = [0xFF, 0xD1];
    private static readonly byte[] PatternPushJmpPop = [0xEB];

    public ShellcodeAnalysisResult AnalyzeBuffer(byte[] data, long baseAddress)
    {
        if (data.Length == 0)
            return new ShellcodeAnalysisResult(false, 0f, [], baseAddress);

        var patterns = new List<string>();
        float score = 0f;

        // 1. Null byte frequency
        var nullCount = 0;
        for (var i = 0; i < data.Length; i++)
            if (data[i] == 0x00) nullCount++;
        var nullRatio = (float)nullCount / data.Length;
        if (nullRatio < 0.005f)
            patterns.Add("LowNullByteFrequency");

        // 2. Common shellcode byte patterns
        if (ContainsPattern(data, PatternMsfvenom))
        {
            score += 0.15f;
            patterns.Add("MsfvenomPrologue");
        }

        if (ContainsPattern(data, PatternCallNext))
        {
            score += 0.15f;
            patterns.Add("CallNextInstruction");
        }

        var callRaxCount = CountPattern(data, PatternCallRax);
        var callRcxCount = CountPattern(data, PatternCallRcx);
        if (callRaxCount + callRcxCount >= 3)
        {
            score += 0.15f;
            patterns.Add($"FrequentIndirectCalls({callRaxCount + callRcxCount})");
        }

        if (HasPushArgPattern(data))
        {
            score += 0.15f;
            patterns.Add("PushArgPattern");
        }

        if (HasJmpShortPopPattern(data))
        {
            score += 0.15f;
            patterns.Add("JmpShortPopPattern");
        }

        // 3. High entropy
        var entropy = CalculateShannonEntropy(data);
        if (entropy > 6.5f)
        {
            score += 0.20f;
            patterns.Add($"HighEntropy({entropy:F2})");
        }

        // 4. ROP chain detection - density of C3 (RET) in 512-byte windows
        if (data.Length >= 512 && HasHighRetDensity(data))
        {
            score += 0.15f;
            patterns.Add("HighRetDensity");
        }

        // 5. Known safe indicators
        if (ContainsAsciiString(data, ".NET CLR") || ContainsAsciiString(data, "MSVCRT"))
        {
            score -= 0.30f;
            patterns.Add("SafeIndicator:ManagedRuntime");
        }

        if (ContainsPeHeader(data))
        {
            score -= 0.20f;
            patterns.Add("SafeIndicator:PeHeader");
        }

        score = Math.Max(0f, score);
        var isLikelyShellcode = score >= 0.4f;

        return new ShellcodeAnalysisResult(isLikelyShellcode, score, patterns.AsReadOnly(), baseAddress);
    }

    private static bool ContainsPattern(byte[] data, byte[] pattern)
    {
        for (var i = 0; i <= data.Length - pattern.Length; i++)
        {
            var match = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    private static int CountPattern(byte[] data, byte[] pattern)
    {
        var count = 0;
        for (var i = 0; i <= data.Length - pattern.Length; i++)
        {
            var match = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) { count++; i += pattern.Length - 1; }
        }
        return count;
    }

    private static bool HasPushArgPattern(byte[] data)
    {
        // 6A XX 68 XX XX XX XX (PUSH byte; PUSH dword)
        for (var i = 0; i <= data.Length - 7; i++)
        {
            if (data[i] == 0x6A && data[i + 2] == 0x68)
                return true;
        }
        return false;
    }

    private static bool HasJmpShortPopPattern(byte[] data)
    {
        // EB XX 59 (JMP short + POP ECX) or EB XX 5? 49
        for (var i = 0; i <= data.Length - 4; i++)
        {
            if (data[i] == 0xEB && data[i + 2] == 0x59)
                return true;
            if (data[i] == 0xEB && i + 3 < data.Length && data[i + 2] == 0x49)
                return true;
        }
        return false;
    }

    private static float CalculateShannonEntropy(byte[] data)
    {
        var freq = new int[256];
        foreach (var b in data) freq[b]++;
        var entropy = 0.0;
        var len = (double)data.Length;
        for (var i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            var p = freq[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return (float)entropy;
    }

    private static bool HasHighRetDensity(byte[] data)
    {
        const int windowSize = 512;
        for (var start = 0; start + windowSize <= data.Length; start += windowSize)
        {
            var retCount = 0;
            for (var i = start; i < start + windowSize; i++)
                if (data[i] == 0xC3) retCount++;
            if (retCount > windowSize / 16)
                return true;
        }
        return false;
    }

    private static bool ContainsAsciiString(byte[] data, string target)
    {
        var targetBytes = System.Text.Encoding.ASCII.GetBytes(target);
        return ContainsPattern(data, targetBytes);
    }

    private static bool ContainsPeHeader(byte[] data)
    {
        // Look for MZ header (4D 5A) followed by PE signature (50 45 00 00) somewhere in the buffer
        for (var i = 0; i <= data.Length - 2; i++)
        {
            if (data[i] == 0x4D && data[i + 1] == 0x5A)
                return true;
        }
        return false;
    }
}
