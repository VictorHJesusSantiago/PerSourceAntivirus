namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IExplorerContextMenuInstaller
{
    Task InstallAsync(string cliExecutablePath, CancellationToken ct = default);
    Task UninstallAsync(CancellationToken ct = default);
    bool IsInstalled();
}
