namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IToastNotificationService
{
    void ShowThreatDetected(string title, string message, string filePath);
    void ShowAlert(string title, string message, int severity);
    void ShowScanComplete(int totalScanned, int threats);
}
