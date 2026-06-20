namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IWindowsEventLogWriter
{
    void WriteInformation(string message, int eventId = 1000);
    void WriteWarning(string message, int eventId = 2000);
    void WriteError(string message, int eventId = 3000);
    void WriteThreatDetected(string threatDescription, string filePath, int severity);
    bool EnsureEventSourceExists();
}
