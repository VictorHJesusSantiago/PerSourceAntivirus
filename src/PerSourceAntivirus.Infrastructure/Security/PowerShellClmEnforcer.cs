using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class PowerShellClmEnforcer : IPowerShellClmEnforcer
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        string lParam,
        uint fuFlags,
        uint uTimeout,
        out IntPtr lpdwResult);

    private const uint WM_SETTINGCHANGE = 0x001A;
    private const uint SMTO_ABORTIFHUNG = 0x0002;
    private static readonly IntPtr HWND_BROADCAST = new(0xFFFF);

    private const string SystemEnvKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    private const string PolicyValueName = "__PSLockdownPolicy";
    private const string ClmValue = "8";

    public bool IsClmEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SystemEnvKey, writable: false);
            if (key != null)
            {
                var value = key.GetValue(PolicyValueName) as string;
                if (value == ClmValue)
                    return true;
            }
        }
        catch
        {
        }

        var envValue = Environment.GetEnvironmentVariable("__PSLockdownPolicy");
        return envValue == ClmValue;
    }

    public bool EnableClm()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SystemEnvKey, writable: true);
            if (key == null)
                return false;

            key.SetValue(PolicyValueName, ClmValue, RegistryValueKind.String);
            BroadcastSettingChange();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool DisableClm()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SystemEnvKey, writable: true);
            if (key == null)
                return false;

            var existing = key.GetValue(PolicyValueName);
            if (existing != null)
            {
                key.DeleteValue(PolicyValueName, throwOnMissingValue: false);
                BroadcastSettingChange();
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void BroadcastSettingChange()
    {
        SendMessageTimeout(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            IntPtr.Zero,
            "Environment",
            SMTO_ABORTIFHUNG,
            5000,
            out _);
    }
}
