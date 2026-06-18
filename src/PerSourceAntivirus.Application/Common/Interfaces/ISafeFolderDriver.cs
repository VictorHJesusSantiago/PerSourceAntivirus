namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISafeFolderDriver
{
    bool IsConnected { get; }
    Task<bool> ConnectAsync(CancellationToken ct = default);
    Task SendAddFolderAsync(string folderPath, CancellationToken ct = default);
    Task SendRemoveFolderAsync(string folderPath, CancellationToken ct = default);
    Task SendAddProcessAsync(string processName, CancellationToken ct = default);
    Task SendRemoveProcessAsync(string processName, CancellationToken ct = default);
    void Disconnect();
}
