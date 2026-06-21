using Microsoft.Win32;

namespace PerSourceAntivirus.Gui.Services;

public sealed class SafeModeScanScheduler
{
    public bool ScheduleRebootScan()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager", true);
            if (key == null) return false;
            var existing = key.GetValue("BootExecute") as string[] ?? ["autocheck autochk *"];
            const string entry = "psav_scan \\DosDevices\\";
            if (!existing.Contains(entry, StringComparer.OrdinalIgnoreCase))
            {
                key.SetValue("BootExecute", existing.Append(entry).ToArray(), RegistryValueKind.MultiString);
            }
            return true;
        }
        catch { return false; }
    }

    public bool IsScanScheduled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager");
            var val = key?.GetValue("BootExecute") as string[] ?? [];
            return val.Any(v => v.Contains("psav_scan", StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }
}
