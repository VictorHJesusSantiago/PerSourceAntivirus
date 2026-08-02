using Microsoft.Extensions.DependencyInjection;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.ProcessInjection;

[SupportedOSPlatform("windows")]
public sealed class NtdllUnhookingDetector : INtdllUnhookingDetector
{
    private readonly Microsoft.Extensions.DependencyInjection.IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<int, DateTime> _alertedProcesses = new();
    private volatile bool _running;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess, IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;

    public event EventHandler<NtdllUnhookingAlertEventArgs>? AlertDetected;

    public NtdllUnhookingDetector(Microsoft.Extensions.DependencyInjection.IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    // [AUDIT FIX — CRITICAL] This detector is a singleton but used to take a *scoped*
    // INtdllUnhookingAlertRepository directly (captive dependency): one AppDbContext captured for the
    // process lifetime and written to from background scan threads, where it is not thread-safe.
    // Scope-per-write is the pattern CLAUDE.md mandates for exactly this reason.
    private async Task PersistAsync(NtdllUnhookingAlert alert, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<INtdllUnhookingAlertRepository>();
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
                await Diagnostics.DetectorScanScope.RunAsync(_scopeFactory, nameof(NtdllUnhookingDetector), () => ScanOnceAsync(ct));
                await Task.Delay(TimeSpan.FromSeconds(20), ct);
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

        var now = DateTime.UtcNow;
        if (_alertedProcesses.TryGetValue(pid, out var last) && (now - last).TotalMinutes < 5)
            return;

        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return;

        try
        {
            var ntdllPaths = GetNtdllModulePaths(handle);

            if (ntdllPaths.Count > 1)
            {
                _alertedProcesses[pid] = now;
                var alert = new NtdllUnhookingAlert
                {
                    Id = Guid.NewGuid(),
                    TargetProcessName = procName,
                    TargetProcessId = pid,
                    MappedNtdllCount = ntdllPaths.Count,
                    MappedPaths = string.Join(",", ntdllPaths),
                    SuspicionReason = "MultipleNtdllMappings",
                    Severity = 9,
                    DetectedAtUtc = now
                };
                await PersistAsync(alert, ct).ConfigureAwait(false);
                AlertDetected?.Invoke(this, new NtdllUnhookingAlertEventArgs(alert));
            }
            else if (ntdllPaths.Count == 1)
            {
                var path = ntdllPaths[0];
                if (!path.Contains("System32", StringComparison.OrdinalIgnoreCase) &&
                    !path.Contains("SysWOW64", StringComparison.OrdinalIgnoreCase))
                {
                    _alertedProcesses[pid] = now;
                    var alert = new NtdllUnhookingAlert
                    {
                        Id = Guid.NewGuid(),
                        TargetProcessName = procName,
                        TargetProcessId = pid,
                        MappedNtdllCount = 1,
                        MappedPaths = path,
                        SuspicionReason = "NtdllFromUnusualPath",
                        Severity = 8,
                        DetectedAtUtc = now
                    };
                    await PersistAsync(alert, ct).ConfigureAwait(false);
                    AlertDetected?.Invoke(this, new NtdllUnhookingAlertEventArgs(alert));
                }
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static List<string> GetNtdllModulePaths(IntPtr handle)
    {
        var result = new List<string>();
        try
        {
            var mods = new IntPtr[1024];
            if (!EnumProcessModules(handle, mods, (uint)(mods.Length * IntPtr.Size), out uint needed))
                return result;

            int count = (int)(needed / (uint)IntPtr.Size);
            var sb = new StringBuilder(1024);

            for (int i = 0; i < count; i++)
            {
                if (mods[i] == IntPtr.Zero) continue;
                sb.Clear();
                if (GetModuleFileNameEx(handle, mods[i], sb, (uint)sb.Capacity) == 0) continue;
                var path = sb.ToString();
                if (path.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                    result.Add(path);
            }
        }
        catch (Exception) { }
        return result;
    }
}
