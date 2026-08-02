using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.DllHijack;

// Detects DLL search-order hijacking / planted DLLs: a module whose file name matches a
// well-known Windows system DLL but is loaded from outside System32/SysWOW64 into a process.
[SupportedOSPlatform("windows")]
public sealed class DllHijackDetector : IDllHijackDetector
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<string, DateTime> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _running;

    private static readonly HashSet<string> KnownSystemDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "kernel32.dll", "user32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
        "comctl32.dll", "shell32.dll", "gdi32.dll", "ws2_32.dll", "version.dll",
        "dwmapi.dll", "uxtheme.dll", "winmm.dll", "propsys.dll", "dbghelp.dll",
        "imm32.dll", "ntdll.dll", "msvcrt.dll", "crypt32.dll", "wininet.dll",
        "urlmon.dll", "secur32.dll", "shlwapi.dll", "setupapi.dll", "winhttp.dll",
        "netapi32.dll", "userenv.dll", "cryptsp.dll", "profapi.dll", "dnsapi.dll"
    };

    private static readonly string System32Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
    private static readonly string SysWow64Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
    private static readonly string WinSxsDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS");

    public event EventHandler<DllHijackAlertEventArgs>? AlertDetected;

    public DllHijackDetector(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    private async Task PersistAsync(DllHijackAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IDllHijackAlertRepository>();
            await repository.AddAsync(alert, ct).ConfigureAwait(false);
        }
        catch { }
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _running = true;
        try
        {
            while (!ct.IsCancellationRequested && _running)
            {
                await Diagnostics.DetectorScanScope.RunAsync(_scopeFactory, nameof(DllHijackDetector), () => ScanOnceAsync(ct));
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _running = false; }
    }

    public void StopMonitoring() => _running = false;

    private async Task ScanOnceAsync(CancellationToken ct)
    {
        SysProcess[] processes;
        try { processes = SysProcess.GetProcesses(); }
        catch (Exception) { return; }

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            try { await ScanProcessAsync(proc, ct); }
            catch (Exception) { }
            finally { proc.Dispose(); }
        }
    }

    private async Task ScanProcessAsync(SysProcess proc, CancellationToken ct)
    {
        int pid;
        string procName;
        try
        {
            pid = proc.Id;
            procName = proc.ProcessName;
        }
        catch (Exception) { return; }

        if (pid <= 4) return;

        System.Diagnostics.ProcessModuleCollection modules;
        try { modules = proc.Modules; }
        catch (Exception) { return; }

        foreach (System.Diagnostics.ProcessModule module in modules)
        {
            string moduleName;
            string modulePath;
            try
            {
                moduleName = module.ModuleName ?? string.Empty;
                modulePath = module.FileName ?? string.Empty;
            }
            catch (Exception) { continue; }
            finally { module.Dispose(); }

            if (moduleName.Length == 0 || modulePath.Length == 0) continue;
            if (!KnownSystemDlls.Contains(moduleName)) continue;

            var dir = Path.GetDirectoryName(modulePath) ?? string.Empty;
            if (IsSystemDirectory(dir)) continue;

            var key = $"{pid}:{moduleName}";
            var now = DateTime.UtcNow;
            if (_alerted.TryGetValue(key, out var last) && (now - last).TotalMinutes < 30) continue;
            _alerted[key] = now;

            var alert = new DllHijackAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = procName,
                ProcessId = pid,
                DllName = moduleName,
                LoadedDllPath = modulePath,
                ExpectedSystemDllPath = Path.Combine(System32Dir, moduleName),
                HijackType = "SearchOrderHijack",
                Severity = 8,
                DetectedAtUtc = now
            };

            await PersistAsync(alert, ct).ConfigureAwait(false);
            AlertDetected?.Invoke(this, new DllHijackAlertEventArgs(alert));
        }
    }

    private static bool IsSystemDirectory(string dir)
    {
        if (dir.Length == 0) return false;
        return dir.StartsWith(System32Dir, StringComparison.OrdinalIgnoreCase) ||
               dir.StartsWith(SysWow64Dir, StringComparison.OrdinalIgnoreCase) ||
               dir.StartsWith(WinSxsDir, StringComparison.OrdinalIgnoreCase);
    }
}
