using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Amsi;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IAmsiProvider, AmsiProviderService>();
[SupportedOSPlatform("windows")]
public sealed class AmsiProviderService : IAmsiProvider
{
    // Use a stable GUID for the PSAV AMSI provider
    private const string ProviderGuid = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}";
    private const string AmsiProvidersKey = @"SOFTWARE\Microsoft\AMSI\Providers";

    public bool IsRegistered { get; private set; }

    public Task RegisterAsync(CancellationToken ct = default)
    {
        try
        {
            // Register CLSID under HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}
            var keyPath = $@"{AmsiProvidersKey}\{ProviderGuid}";
            using var key = Registry.LocalMachine.CreateSubKey(keyPath, writable: true);
            key?.SetValue("", "PerSourceAntivirus AMSI Provider", RegistryValueKind.String);

            // Also register under HKLM\SOFTWARE\Classes\CLSID\{GUID}\InProcServer32
            // pointing to our CLI/service executable
            var exePath = Environment.ProcessPath
                ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                ?? string.Empty;
            var clsidPath = $@"SOFTWARE\Classes\CLSID\{ProviderGuid}\InProcServer32";
            using var clsidKey = Registry.LocalMachine.CreateSubKey(clsidPath, writable: true);
            clsidKey?.SetValue("", exePath, RegistryValueKind.String);
            clsidKey?.SetValue("ThreadingModel", "Both", RegistryValueKind.String);

            IsRegistered = true;
        }
        catch (UnauthorizedAccessException)
        {
            // Requires elevation — silently fail; caller checks IsRegistered
        }
        return Task.CompletedTask;
    }

    public Task UnregisterAsync(CancellationToken ct = default)
    {
        try
        {
            Registry.LocalMachine.DeleteSubKeyTree($@"{AmsiProvidersKey}\{ProviderGuid}", throwOnMissingSubKey: false);
            Registry.LocalMachine.DeleteSubKeyTree($@"SOFTWARE\Classes\CLSID\{ProviderGuid}", throwOnMissingSubKey: false);
            IsRegistered = false;
        }
        catch (UnauthorizedAccessException) { }
        return Task.CompletedTask;
    }
}
