using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISafeFolderService
{
    IReadOnlyList<string> GetProtectedFolders();
    void AddProtectedFolder(string folderPath);
    void RemoveProtectedFolder(string folderPath);
    IReadOnlyList<string> GetWhitelistedProcesses();
    void AddWhitelistedProcess(string processName);
    void RemoveWhitelistedProcess(string processName);
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<SafeFolderViolationAlertEventArgs> ViolationDetected;
}

public record SafeFolderViolationAlertEventArgs(SafeFolderViolationAlert Alert);
