using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ComHijack;

public sealed class ComHijackMonitor : IComHijackMonitor, IDisposable
{
    private static readonly string[] SystemPaths =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
        Environment.GetFolderPath(Environment.SpecialFolder.Windows)
    ];

    private static readonly string[] TrustedPrefixes =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData")
    ];

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(
        IntPtr hProcess,
        [Out] IntPtr[] lphModule,
        uint cb,
        out uint lpcbNeeded,
        uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameEx(
        IntPtr hProcess,
        IntPtr hModule,
        StringBuilder lpFilename,
        uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegNotifyChangeKeyValue(
        IntPtr hKey,
        bool bWatchSubtree,
        int dwNotifyFilter,
        IntPtr hEvent,
        bool fAsynchronous);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const int LIST_MODULES_ALL = 0x03;
    private const int REG_NOTIFY_CHANGE_NAME = 0x01;
    private const int REG_NOTIFY_CHANGE_LAST_SET = 0x04;

    private bool _disposed;

    public async Task<IReadOnlyList<ComHijackAlert>> ScanCurrentStateAsync(CancellationToken ct = default)
    {
        var alerts = new List<ComHijackAlert>();

        await Task.Run(() =>
        {
            ScanComHijackRegistry(alerts, ct);
            ScanDllSideloading(alerts, ct);
        }, ct);

        return alerts.AsReadOnly();
    }

    public async IAsyncEnumerable<ComHijackAlert> WatchAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        RegistryKey? hkcu = null;
        RegistryKey? clsidKey = null;

        try
        {
            hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            clsidKey = hkcu.OpenSubKey(@"Software\Classes\CLSID", writable: false);

            if (clsidKey == null) yield break;

            while (!ct.IsCancellationRequested)
            {
                // Wait for registry change notification
                var waitResult = await WaitForRegistryChangeAsync(clsidKey, ct);
                if (!waitResult || ct.IsCancellationRequested) break;

                // Re-scan and yield new alerts
                var alerts = new List<ComHijackAlert>();
                ScanComHijackRegistry(alerts, ct);

                foreach (var alert in alerts)
                    yield return alert;
            }
        }
        finally
        {
            clsidKey?.Dispose();
            hkcu?.Dispose();
        }
    }

    private static void ScanComHijackRegistry(List<ComHijackAlert> alerts, CancellationToken ct)
    {
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var hkcrHkcu = hkcu.OpenSubKey(@"Software\Classes\CLSID", writable: false);
            if (hkcrHkcu == null) return;

            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var hklmClsid = hklm.OpenSubKey(@"Software\Classes\CLSID", writable: false);

            foreach (var clsidName in hkcrHkcu.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                // Check if same CLSID exists in HKLM (override scenario)
                var hklmEntry = hklmClsid?.OpenSubKey(clsidName, writable: false);
                if (hklmEntry == null) continue;

                // HKCU entry overrides HKLM — potential COM hijack
                using var hkcuEntry = hkcrHkcu.OpenSubKey(clsidName, writable: false);
                if (hkcuEntry == null) continue;

                var inprocPath = GetInprocServer32Path(hkcuEntry);
                if (string.IsNullOrEmpty(inprocPath)) continue;

                if (IsOutsideSystemDirectories(inprocPath))
                {
                    var legitimatePath = GetInprocServer32Path(hklmEntry);
                    alerts.Add(new ComHijackAlert
                    {
                        DetectedAtUtc = DateTime.UtcNow,
                        AlertType = "ComHijack",
                        ClsidOrPath = clsidName,
                        SuspiciousPath = inprocPath,
                        LegitimateSystemPath = legitimatePath,
                        Severity = "High"
                    });
                }

                hklmEntry.Dispose();
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Registry access may fail on non-Windows or without permissions
        }
    }

    private static string? GetInprocServer32Path(RegistryKey clsidKey)
    {
        try
        {
            using var inproc = clsidKey.OpenSubKey("InprocServer32", writable: false);
            return inproc?.GetValue(null)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static bool IsOutsideSystemDirectories(string path)
    {
        var fullPath = Environment.ExpandEnvironmentVariables(path);
        return !SystemPaths.Any(sp =>
            fullPath.StartsWith(sp, StringComparison.OrdinalIgnoreCase));
    }

    private static void ScanDllSideloading(List<ComHijackAlert> alerts, CancellationToken ct)
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var sysWow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

        foreach (var proc in SysProcess.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                if (hProcess == IntPtr.Zero) continue;

                try
                {
                    var modules = GetProcessModules(hProcess);
                    foreach (var modulePath in modules)
                    {
                        if (string.IsNullOrEmpty(modulePath)) continue;
                        if (IsFromTrustedPath(modulePath)) continue;

                        var dllName = Path.GetFileName(modulePath);
                        var system32Path = Path.Combine(system32, dllName);
                        var sysWow64Path = Path.Combine(sysWow64, dllName);

                        string? legitimatePath = null;
                        if (File.Exists(system32Path))
                            legitimatePath = system32Path;
                        else if (File.Exists(sysWow64Path))
                            legitimatePath = sysWow64Path;

                        if (legitimatePath != null)
                        {
                            alerts.Add(new ComHijackAlert
                            {
                                DetectedAtUtc = DateTime.UtcNow,
                                AlertType = "DllSideload",
                                ClsidOrPath = $"PID:{proc.Id} ({proc.ProcessName})",
                                SuspiciousPath = modulePath,
                                LegitimateSystemPath = legitimatePath,
                                Severity = "High"
                            });
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // skip inaccessible processes
            }
            finally
            {
                try { proc.Dispose(); } catch { }
            }
        }
    }

    private static List<string> GetProcessModules(IntPtr hProcess)
    {
        var result = new List<string>();
        var modules = new IntPtr[1024];

        if (!EnumProcessModulesEx(hProcess, modules, (uint)(modules.Length * IntPtr.Size), out var needed, LIST_MODULES_ALL))
            return result;

        var count = (int)(needed / (uint)IntPtr.Size);
        for (var i = 0; i < Math.Min(count, modules.Length); i++)
        {
            var sb = new StringBuilder(260);
            if (GetModuleFileNameEx(hProcess, modules[i], sb, (uint)sb.Capacity) > 0)
                result.Add(sb.ToString());
        }

        return result;
    }

    private static bool IsFromTrustedPath(string modulePath)
    {
        return TrustedPrefixes.Any(prefix =>
            !string.IsNullOrEmpty(prefix) &&
            modulePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static Task<bool> WaitForRegistryChangeAsync(RegistryKey regKey, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using var eventHandle = new System.Threading.ManualResetEventSlim(false);
                var nativeEvent = eventHandle.WaitHandle.SafeWaitHandle.DangerousGetHandle();

                var notifyFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;
                var result = RegNotifyChangeKeyValue(
                    regKey.Handle.DangerousGetHandle(),
                    bWatchSubtree: true,
                    notifyFilter,
                    nativeEvent,
                    fAsynchronous: true);

                if (result != 0) return false;

                // Wait for the event or cancellation
                var idx = System.Threading.WaitHandle.WaitAny(
                    [eventHandle.WaitHandle, ct.WaitHandle],
                    TimeSpan.FromSeconds(30));

                return idx == 0; // 0 = registry change, 1 = cancellation
            }
            catch
            {
                return false;
            }
        }, ct);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
    }
}
