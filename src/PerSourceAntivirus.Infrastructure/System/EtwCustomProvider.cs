using System.Diagnostics.Tracing;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[EventSource(Name = "PerSourceAntivirus-Provider", Guid = "A3D1E5F8-9B2C-4D67-8E10-F5A6B7C8D9E0")]
public sealed class PerSourceAntivirusEventSource : EventSource
{
    public static readonly PerSourceAntivirusEventSource Log = new();

    [Event(1, Level = EventLevel.Informational)]
    public void ThreatDetected(string alertType, int severity, string details)
        => WriteEvent(1, alertType, severity, details);

    [Event(2, Level = EventLevel.Warning)]
    public void ScanCompleted(int totalFiles, int threats)
        => WriteEvent(2, totalFiles, threats);

    [Event(3, Level = EventLevel.Critical)]
    public void CriticalAlert(string message, string processName)
        => WriteEvent(3, message, processName);
}

[SupportedOSPlatform("windows")]
public sealed class EtwCustomProvider : IEtwCustomProvider
{
    public Guid ProviderId => Guid.Parse("A3D1E5F8-9B2C-4D67-8E10-F5A6B7C8D9E0");
    public string ProviderName => "PerSourceAntivirus-Provider";

    public void WriteEvent(string eventName, string payload)
        => PerSourceAntivirusEventSource.Log.ThreatDetected(eventName, 0, payload);

    public void WriteThreatEvent(string alertType, int severity, string details)
        => PerSourceAntivirusEventSource.Log.ThreatDetected(alertType, severity, details);
}
