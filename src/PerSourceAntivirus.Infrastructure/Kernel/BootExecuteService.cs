using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Kernel;

[SupportedOSPlatform("windows")]
public sealed class BootExecuteService : IBootExecuteService
{
    private const string SessionManagerKey = @"SYSTEM\CurrentControlSet\Control\Session Manager";
    private const string BootExecuteValue  = "BootExecute";
    private const string PsavEntry         = @"psavboot";

    public Task RegisterAsync(CancellationToken ct = default)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SessionManagerKey, writable: true);
            if (key is null) return Task.CompletedTask;

            var current = key.GetValue(BootExecuteValue) as string[] ?? ["autocheck autochk *"];
            if (!current.Any(e => e.Contains(PsavEntry, StringComparison.OrdinalIgnoreCase)))
            {
                var updated = current.Append(PsavEntry).ToArray();
                key.SetValue(BootExecuteValue, updated, RegistryValueKind.MultiString);
            }
        }
        catch { }
        return Task.CompletedTask;
    }

    public Task UnregisterAsync(CancellationToken ct = default)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SessionManagerKey, writable: true);
            if (key is null) return Task.CompletedTask;

            var current = key.GetValue(BootExecuteValue) as string[] ?? [];
            var filtered = current.Where(e => !e.Contains(PsavEntry, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (filtered.Length < current.Length)
                key.SetValue(BootExecuteValue, filtered, RegistryValueKind.MultiString);
        }
        catch { }
        return Task.CompletedTask;
    }

    public Task<bool> IsRegisteredAsync(CancellationToken ct = default)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SessionManagerKey, writable: false);
            if (key is null) return Task.FromResult(false);
            var current = key.GetValue(BootExecuteValue) as string[] ?? [];
            return Task.FromResult(current.Any(e => e.Contains(PsavEntry, StringComparison.OrdinalIgnoreCase)));
        }
        catch
        {
            return Task.FromResult(false);
        }
    }
}
