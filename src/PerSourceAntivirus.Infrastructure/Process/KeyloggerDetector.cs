using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Process;

[SupportedOSPlatform("windows")]
public sealed class KeyloggerDetector : IKeyloggerDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private volatile bool _running;

    public bool TryTerminateSuspiciousProcess { get; set; } = false;

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

    public KeyloggerDetector(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    private async Task PersistAsync(KeyloggerDetectionAlert alert)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IKeyloggerAlertRepository>();
            await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
    }

    private const string Win32kProviderGuid = "8c416c79-d49b-4f01-a467-e56d3aa8234c";
    private static readonly HashSet<int> KeyboardHookTypes = [2, 13];

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;

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
                    if (!e.EventName.Contains("Hook", StringComparison.OrdinalIgnoreCase)) return;

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
        try
        {
            var processes = SysProcess.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    var procName = proc.ProcessName;
                    string mainModulePath;
                    try { mainModulePath = proc.MainModule?.FileName ?? ""; }
                    catch { mainModulePath = ""; }

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
        if (string.IsNullOrEmpty(modulePath)) return false;

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
        await Task.Delay(100, ct);

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

        _ = PersistAsync(alert);
        AlertDetected?.Invoke(this, new KeyloggerDetectionAlertEventArgs(alert));
    }
}
