namespace PerSourceAntivirus.Domain.Alerts;

public static class AlertSeverity
{
    public const int Minimum = 1;

    public const int Maximum = 10;

    public const int Low = 3;

    public const int Medium = 5;

    public const int High = 7;

    public const int CriticalThreshold = 8;

    public const int HighThreshold = Medium;

    public static bool IsCritical(int severity) => severity >= CriticalThreshold;

    public static bool IsInRange(int severity) => severity is >= Minimum and <= Maximum;

    public static int Clamp(int severity) => Math.Clamp(severity, Minimum, Maximum);

    public static string ToLabel(int severity) =>
        severity >= CriticalThreshold ? "CRITICAL"
        : severity >= HighThreshold ? "HIGH"
        : "LOW";
}
