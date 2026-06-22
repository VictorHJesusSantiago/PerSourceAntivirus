using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Process;

[SupportedOSPlatform("windows")]
public sealed class KeyloggerDetector : IKeyloggerDetector
{
    private readonly IKeyloggerAlertRepository _repository;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    public bool TryTerminateSuspiciousProcess { get; set; } = false;

    // Known legitimate keyboard filter drivers
    private static readonly HashSet<string> KnownLegitimateDrivers = new(StringComparer.OrdinalIgnoreCase)
    {
        "kbdclass", "kbdhid", "i8042prt", "hidusb", "mouhid", "mouclass",
        "acpiex", "acpi", "compbatt", "battc", "vhidmini"
    };

    [DllImport("user32.dll")]
    private static extern uint GetRegisteredRawInputDevices(
        IntPtr pRawInputDevices, ref uint puiNumDevices, uint cbSize);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    public event EventHandler<KeyloggerDetectionAlertEventArgs>? AlertDetected;

    public KeyloggerDetector(IKeyloggerAlertRepository repository)
    {
        _repository = repository;
    }

    // ETW provider: Microsoft-Windows-Win32k detects cross-process SetWindowsHookEx calls
    private const string Win32kProviderGuid = "8c416c79-d49b-4f01-a467-e56d3aa8234c";
    // WH_KEYBOARD=2, WH_KEYBOARD_LL=13
    private static readonly HashSet<int> KeyboardHookTypes = [2, 13];

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;

        // Start ETW Win32k hook monitor on a background thread (requires admin)
        var etwTask = Task.Run(() => RunWin32kEtwMonitor(ct), ct);

        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try
                {
                    ScanKeyboardFilterDrivers();
                    ScanRawInputRegistrations();
                    await ScanProcessHooksAsync(ct);
                    ScanGetAsyncKeyStateImports();
                }
                catch { }
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            _running = false;
            try { await etwTask.WaitAsync(TimeSpan.FromSeconds(3), CancellationToken.None); } catch { }
        }
    }

    private void RunWin32kEtwMonitor(CancellationToken ct)
    {
        TraceEventSession? session = null;
        try
        {
            session = new TraceEventSession("psav-keylogger-win32k");
            session.EnableProvider(Win32kProviderGuid);

            ct.Register(() => session?.Stop());

            session.Source.Dynamic.All += e =>
            {
                try
                {
                    // Look for SetWindowsHookEx-related events; hook type is carried in payload fields
                    // The Win32k provider uses event name "SetWindowsHookEx" or similar
                    if (!e.EventName.Contains("Hook", StringComparison.OrdinalIgnoreCase)) return;

                    // Try to read hook type from payload
                    int hookType = -1;
                    try { hookType = (int)e.PayloadValue(0); } catch { }

                    if (hookType >= 0 && !KeyboardHookTypes.Contains(hookType)) return;

                    int callerPid = e.ProcessID;
                    string callerName = "Unknown";
                    try
                    {
                        using var proc = SysProcess.GetProcessById(callerPid);
                        callerName = proc.ProcessName;
                        string path;
                        try { path = proc.MainModule?.FileName ?? ""; } catch { path = ""; }
                        // Skip system processes
                        if (path.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) ||
                            path.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase))
                            return;
                    }
                    catch { }

                    FireAlert(callerName, callerPid, "Win32k-ETW-Hook",
                        $"Process {callerName} (PID {callerPid}) installed keyboard hook type {hookType} via SetWindowsHookEx",
                        e.EventName);
                }
                catch { }
            };

            session.Source.Process();
        }
        catch
        {
            // Non-admin or provider not available — silently skip ETW path
        }
        finally
        {
            session?.Dispose();
        }
    }

    public void StopMonitoring() => _running = false;

    private void ScanKeyboardFilterDrivers()
    {
        const string keyboardClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyboardClassKey);
            if (key is null) return;

            var upperFilters = key.GetValue("UpperFilters") as string[] ?? [];
            foreach (var filter in upperFilters)
            {
                var trimmed = filter.Trim();
                if (!string.IsNullOrEmpty(trimmed) && !KnownLegitimateDrivers.Contains(trimmed))
                {
                    FireAlert("Unknown", 0, "KeyboardFilterDriver",
                        $"Unknown keyboard UpperFilter driver: {trimmed}",
                        $@"\SYSTEM\CurrentControlSet\services\{trimmed}");
                }
            }

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                using var subKey = key.OpenSubKey(subKeyName);
                if (subKey is null) continue;
                var filters = subKey.GetValue("UpperFilters") as string[] ?? [];
                foreach (var filter in filters)
                {
                    var trimmed = filter.Trim();
                    if (!string.IsNullOrEmpty(trimmed) && !KnownLegitimateDrivers.Contains(trimmed))
                    {
                        FireAlert("Unknown", 0, "KeyboardFilterDriver",
                            $"Keyboard device {subKeyName} has unknown UpperFilter: {trimmed}",
                            trimmed);
                    }
                }
            }
        }
        catch { }
    }

    private void ScanRawInputRegistrations()
    {
        // Enumerate all running processes and check which ones have RawInput keyboard sinks
        // This is done indirectly: check processes with GetRegisteredRawInputDevices
        // We can only call this for the current process; for others we'd need a hook
        // Instead scan for suspicious window hooks via ETW or check running processes
        try
        {
            var processes = SysProcess.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    var procName = proc.ProcessName;
                    // Flag processes outside system paths that have keyboard hook patterns in name/path
                    string mainModulePath;
                    try { mainModulePath = proc.MainModule?.FileName ?? ""; }
                    catch { mainModulePath = ""; }

                    // Check if process loaded keyboard-related modules
                    if (IsSuspiciousKeyloggerProcess(proc, mainModulePath))
                    {
                        FireAlert(procName, proc.Id, "RawInputSink",
                            $"Process {procName} (PID {proc.Id}) exhibits keylogger behavior patterns",
                            mainModulePath);
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private static bool IsSuspiciousKeyloggerProcess(SysProcess proc, string modulePath)
    {
        // Heuristic: process has very low privilege, is not in system dir,
        // and has modules with keyboard-related names
        if (string.IsNullOrEmpty(modulePath)) return false;

        // Skip system processes
        if (modulePath.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) ||
            modulePath.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) ||
            modulePath.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
            {
                var modName = mod.ModuleName?.ToLowerInvariant() ?? "";
                if (modName.Contains("keylog") || modName.Contains("klog") ||
                    modName.Contains("keystroke") || modName.Contains("keyhook"))
                    return true;
            }
        }
        catch { }
        return false;
    }

    private async Task ScanProcessHooksAsync(CancellationToken ct)
    {
        // Check Windows hook registrations via WMI (SetWindowsHookEx creates entries detectable via ETW)
        // Also check if any non-system DLLs are loaded in multiple processes (common hook pattern)
        // This is a lightweight heuristic scan
        await Task.Delay(100, ct); // yield

        // Check if any running process has a non-system DLL in multiple other processes
        // This is a simplified check — full detection requires ETW subscription
        try
        {
            var processes = SysProcess.GetProcesses();
            var moduleCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in processes)
            {
                try
                {
                    foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                    {
                        var path = mod.FileName ?? "";
                        if (!path.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) &&
                            !path.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase))
                        {
                            moduleCounts.TryGetValue(path, out var count);
                            moduleCounts[path] = count + 1;
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            // A non-system DLL loaded in many processes is typical of a global hook
            foreach (var kv in moduleCounts.Where(m => m.Value >= 5))
            {
                FireAlert("Unknown", 0, "WH_KEYBOARD_LL_Hook",
                    $"Non-system DLL loaded in {kv.Value} processes (possible global hook): {kv.Key}",
                    kv.Key);
            }
        }
        catch { }
    }

    private void ScanGetAsyncKeyStateImports()
    {
        try
        {
            foreach (var proc in SysProcess.GetProcesses())
            {
                try
                {
                    string mainModulePath;
                    try { mainModulePath = proc.MainModule?.FileName ?? string.Empty; }
                    catch { continue; }

                    if (string.IsNullOrEmpty(mainModulePath)) continue;
                    if (mainModulePath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) ||
                        mainModulePath.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase))
                        continue;

                    try
                    {
                        foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                        {
                            if (string.Equals(mod.ModuleName, "user32.dll", StringComparison.OrdinalIgnoreCase))
                            {
                                FireAlert(proc.ProcessName, proc.Id, "GetAsyncKeyState-Import",
                                    $"Non-system process {proc.ProcessName} uses user32.dll (potential GetAsyncKeyState abuse)",
                                    mainModulePath);
                                break;
                            }
                        }
                    }
                    catch { }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private void FireAlert(string processName, int pid, string method, string detail, string modulePath)
    {
        var key = $"{method}_{modulePath}";
        var now = DateTime.UtcNow;
        if (_recentAlerts.TryGetValue(key, out var last) && (now - last).TotalMinutes < 30) return;
        _recentAlerts[key] = now;

        var alert = new KeyloggerDetectionAlert
        {
            Id = Guid.NewGuid(),
            ProcessName = processName,
            ProcessId   = pid,
            DetectionMethod = method,
            SuspiciousDetail = detail,
            ModulePath  = modulePath,
            Severity    = 7,
            DetectedAtUtc = now
        };

        try { _repository.AddAsync(alert).GetAwaiter().GetResult(); } catch { }
        AlertDetected?.Invoke(this, new KeyloggerDetectionAlertEventArgs(alert));
    }
}
