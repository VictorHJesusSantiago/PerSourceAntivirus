namespace PerSourceAntivirus.Application.Common.Interfaces;

// Registers/removes a "Scan with PerSourceAntivirus" entry in the Windows Explorer right-click
// menu for files and folders, via registry shell verbs (HKCR\*\shell, HKCR\Directory\shell).
public interface IExplorerContextMenuInstaller
{
    Task InstallAsync(string cliExecutablePath, CancellationToken ct = default);
    Task UninstallAsync(CancellationToken ct = default);
    bool IsInstalled();
}
