namespace PerSourceAntivirus.Infrastructure.Detection.Heuristics;

public static class CryptojackingHeuristics
{
    public static readonly IReadOnlySet<int> MiningPoolPorts = new HashSet<int>
    {
        3333, 3334, 3335, 3336, 4444, 5555, 5556, 7777, 8080, 8888,
        9999, 14444, 14433, 45700, 4028, 3032, 1800, 8118, 20535
    };

    public const double SustainedHighCpuPercent = 80.0;

    public static bool IsMiningPoolPort(int port) => MiningPoolPorts.Contains(port);

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

    public static CryptojackingVerdict? Evaluate(bool hasMiningPoolConnection, double cpuPercent)
    {
        if (!hasMiningPoolConnection) return null;

        return cpuPercent >= SustainedHighCpuPercent
            ? new CryptojackingVerdict("MiningPoolPortAndHighCpu", 9)
            : new CryptojackingVerdict("MiningPoolPort", 6);
    }
}

public record CryptojackingVerdict(string Reason, int Severity);
