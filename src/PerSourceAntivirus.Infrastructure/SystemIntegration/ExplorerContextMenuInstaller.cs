using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public sealed class ExplorerContextMenuInstaller : IExplorerContextMenuInstaller
{
    private const string VerbName = "PerSourceAntivirusScan";
    private const string MenuText = "Escanear com PerSourceAntivirus";

    // Roots that get the "Scan with..." verb: individual files and folders.
    private static readonly string[] ShellRoots = { @"*\shell", @"Directory\shell" };

    public Task InstallAsync(string cliExecutablePath, CancellationToken ct = default)
    {
        var command = $"\"{cliExecutablePath}\" scan \"%1\"";

        foreach (var shellRoot in ShellRoots)
        {
            using var verbKey = Registry.ClassesRoot.CreateSubKey($@"{shellRoot}\{VerbName}");
            verbKey?.SetValue(string.Empty, MenuText);
            verbKey?.SetValue("Icon", $"\"{cliExecutablePath}\",0");

            using var commandKey = Registry.ClassesRoot.CreateSubKey($@"{shellRoot}\{VerbName}\command");
            commandKey?.SetValue(string.Empty, command);
        }

        return Task.CompletedTask;
    }

    public Task UninstallAsync(CancellationToken ct = default)
    {
        foreach (var shellRoot in ShellRoots)
        {
            try { Registry.ClassesRoot.DeleteSubKeyTree($@"{shellRoot}\{VerbName}", throwOnMissingSubKey: false); }
            catch { }
        }

        return Task.CompletedTask;
    }

    public bool IsInstalled()
    {
        using var key = Registry.ClassesRoot.OpenSubKey($@"*\shell\{VerbName}");
        return key is not null;
    }
}
