namespace PerSourceAntivirus.Infrastructure.Detection.Heuristics;

// Pure decision logic for cryptojacking detection, split out of CryptojackingDetector so the
// correlation rules can be tested without live processes or a TCP table.
public static class CryptojackingHeuristics
{
    // Stratum and common XMR/ETH pool ports.
    public static readonly IReadOnlySet<int> MiningPoolPorts = new HashSet<int>
    {
        3333, 3334, 3335, 3336, 4444, 5555, 5556, 7777, 8080, 8888,
        9999, 14444, 14433, 45700, 4028, 3032, 1800, 8118, 20535
    };

    public const double SustainedHighCpuPercent = 80.0;

    public static bool IsMiningPoolPort(int port) => MiningPoolPorts.Contains(port);

    // CPU% between two samples, normalised across all cores and clamped to 0-100.
    // Returns 0 when the window is non-positive, so a first observation cannot alert.
    public static double CalculateCpuPercent(
        TimeSpan previousCpuTime, TimeSpan currentCpuTime,
        DateTime previousSampleAt, DateTime currentSampleAt,
        int processorCount)
    {
        var elapsedWallMs = (currentSampleAt - previousSampleAt).TotalMilliseconds * processorCount;
        if (elapsedWallMs <= 0) return 0;

        var elapsedCpuMs = (currentCpuTime - previousCpuTime).TotalMilliseconds;
        return Math.Max(0, Math.Min(100, elapsedCpuMs / elapsedWallMs * 100));
    }

    // High CPU on its own is deliberately NOT an alert: compilers, games and video encoders all
    // pin the CPU. Only a connection to a known pool port makes it a mining signal.
    public static CryptojackingVerdict? Evaluate(bool hasMiningPoolConnection, double cpuPercent)
    {
        if (!hasMiningPoolConnection) return null;

        return cpuPercent >= SustainedHighCpuPercent
            ? new CryptojackingVerdict("MiningPoolPortAndHighCpu", 9)
            : new CryptojackingVerdict("MiningPoolPort", 6);
    }
}

public record CryptojackingVerdict(string Reason, int Severity);
