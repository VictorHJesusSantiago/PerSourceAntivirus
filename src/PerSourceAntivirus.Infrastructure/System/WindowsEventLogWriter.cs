using System.Diagnostics;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogWriter : IWindowsEventLogWriter
{
    private const string Source = "PerSourceAntivirus";
    private const string LogName = "Application";

    public bool EnsureEventSourceExists()
    {
        try
        {
            if (!EventLog.SourceExists(Source))
                EventLog.CreateEventSource(Source, LogName);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void WriteInformation(string message, int eventId = 1000)
    {
        try
        {
            using var log = new EventLog(LogName) { Source = Source };
            log.WriteEntry(message, EventLogEntryType.Information, eventId);
        }
        catch { }
    }

    public void WriteWarning(string message, int eventId = 2000)
    {
        try
        {
            using var log = new EventLog(LogName) { Source = Source };
            log.WriteEntry(message, EventLogEntryType.Warning, eventId);
        }
        catch { }
    }

    public void WriteError(string message, int eventId = 3000)
    {
        try
        {
            using var log = new EventLog(LogName) { Source = Source };
            log.WriteEntry(message, EventLogEntryType.Error, eventId);
        }
        catch { }
    }

    public void WriteThreatDetected(string threatDescription, string filePath, int severity)
        => WriteWarning($"Threat detected (severity {severity}): {threatDescription} | File: {filePath}", 2001);
}
